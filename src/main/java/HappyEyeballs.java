/*
 * Copyright 2021  Oleg Muravskiy
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following
 * conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Type;

import java.io.Closeable;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.time.Duration;
import java.util.Iterator;
import java.util.Optional;
import java.util.Queue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * A slightly loose implementation of the "Happy Eyeballs" mechanism described in the
 * <a href="https://tools.ietf.org/html/rfc8305">RFC 8305</a>. If the given hostname resolves to several IP addresses,
 * it will try to connect to those addresses concurrently, giving slight preference to IPv6, and will return the address
 * of first successful connection.
 *
 * <p>This class is thread safe. Instantiate it once and re-use as appropriate.
 */
public class HappyEyeballs {

    // delays as in RFC8305/Section 8
    private static final long RESOLUTION_DELAY_MILLIS = 50L;
    private static final long CONNECTION_ATTEMPT_DELAY_MILLIS = 250L;

    public static final long HAPPY_EYEBALLS_TOTAL_TIMEOUT_NANOS = TimeUnit.SECONDS.toNanos(10);

    private static final Pattern IPV4_ADDRESS_PATTERN = Pattern.compile("\\d{1,3}(?:\\.\\d{1,3}){3}");
    private static final Pattern IPV6_ADDRESS_PATTERN =
            Pattern.compile("( [0-9A-Fa-f:.]+ (?: % [0-9A-Za-z][-0-9A-Za-z_\\ ]*)? )", Pattern.COMMENTS);

    private static final Logger log = LoggerFactory.getLogger(HappyEyeballs.class);
    private final ExecutorService executor;

    /**
     * Create an instance with default {@link ExecutorService} (which is a CachedThreadPool at the moment).
     */
    public HappyEyeballs() {
        executor = Executors.newCachedThreadPool();
    }

    /**
     * Create an instance of HappyEyeballs.
     *
     * @param executor The {@link ExecutorService} to use for async executions (DNS lookups and the main Future returned)
     */
    public HappyEyeballs(ExecutorService executor) {
        this.executor = executor;
    }

    /**
     * Resolve given hostname and perform the "Happy Eyeballs v.2" selection of the best address by connecting to given port.
     * Returned Future will be completed after first successful connection or canceled in case of errors or after
     * timeout expiration (10 seconds).
     *
     * @param host hostname to resolve
     * @param port port to connect to
     * @return The {@link CompletableFuture} of {@link SocketAddress} that holds IP address of the first successful connection
     */
    public CompletableFuture<SocketAddress> resolve(String host, int port) {
        final Optional<String> literalIpAddress = isLiteralIpAddress(host);
        return literalIpAddress.map(ipAddress ->
                CompletableFuture.completedFuture((SocketAddress) new InetSocketAddress(ipAddress, port)))
                .orElse(CompletableFuture.supplyAsync(() -> resolveAndFindBestAddress(host, port)));
    }

    private SocketAddress resolveAndFindBestAddress(String host, int port) {
        Selector selector = null;
        try {
            final Name hostname = Name.fromString(host);

            final ConcurrentLinkedQueue<Optional<InetAddress>> resolvedAddressesV6 = new ConcurrentLinkedQueue<>();
            executor.execute(dnsLookupRunnable(hostname, Type.AAAA, resolvedAddressesV6));

            final ConcurrentLinkedQueue<Optional<InetAddress>> resolvedAddressesV4 = new ConcurrentLinkedQueue<>();
            executor.execute(dnsLookupRunnable(hostname, Type.A, resolvedAddressesV4));

            awaitDnsResponses(resolvedAddressesV6, resolvedAddressesV4);

            if (log.isInfoEnabled()) {
                log.info("Resolved v6 addresses: {} for host {}", joinAddresses(resolvedAddressesV6), host);
                log.info("Resolved v4 addresses: {} for host {}", joinAddresses(resolvedAddressesV4), host);
            }

            selector = Selector.open();
            return findBestAddress(resolvedAddressesV6, resolvedAddressesV4, port, selector)
                    .orElseThrow(() -> new IOException(String.format("Could not connect to %s:%d in %s",
                            host, port, Duration.ofNanos(HAPPY_EYEBALLS_TOTAL_TIMEOUT_NANOS))));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } finally {
            if (selector != null && selector.isOpen()) {
                for (SelectionKey key : selector.keys()) {
                    closeAnyway(key.channel());
                }
                closeAnyway(selector);
            }
        }
    }

    private static Optional<SocketAddress> findBestAddress(final Queue<Optional<InetAddress>> firstAfAddresses,
                                                           final Queue<Optional<InetAddress>> secondAfAddresses,
                                                           final int port, final Selector selector) {
        final long startTime = System.nanoTime();
        final long deadline = startTime + HAPPY_EYEBALLS_TOTAL_TIMEOUT_NANOS;
        Optional<SocketAddress> connectedSocket;
        boolean keepGoing = true;
        while (keepGoing && !Thread.currentThread().isInterrupted()) {
            final boolean haveMoreAF1 = openConnectionFromQueue(firstAfAddresses, port, selector);
            connectedSocket = awaitSuccessfulConnection(selector, CONNECTION_ATTEMPT_DELAY_MILLIS);
            if (connectedSocket.isPresent()) return connectedSocket;

            final boolean haveMoreAF2 = openConnectionFromQueue(secondAfAddresses, port, selector);
            connectedSocket = awaitSuccessfulConnection(selector, CONNECTION_ATTEMPT_DELAY_MILLIS);
            if (connectedSocket.isPresent()) return connectedSocket;

            // watch out! do not inline these booleans,
            // otherwise you'll shortcircuit second evaluation
            keepGoing = (haveMoreAF1 || haveMoreAF2) && haveTime(deadline);
        }
        if (selector.keys().isEmpty()) {
            return Optional.empty();
        } else {
            final long remainingTime = Math.max(0, deadline - System.nanoTime());
            return awaitSuccessfulConnection(selector, TimeUnit.NANOSECONDS.toMillis(remainingTime));
        }
    }

    private static Optional<SocketAddress> awaitSuccessfulConnection(Selector selector, long selectTimeoutMs) {
        int count = 0;
        try {
            count = (selectTimeoutMs > 0) ? selector.select(selectTimeoutMs) : selector.selectNow();
        } catch (IOException e) {
            log.warn("Error awaiting for connect: ", e);
        }
        if (count > 0) {
            final Iterator<SelectionKey> iterator = selector.selectedKeys().iterator();
            while (iterator.hasNext()) {
                SelectionKey key = iterator.next();
                final SocketChannel socketChannel = (SocketChannel) key.channel();
                try {
                    if (socketChannel.finishConnect()) {
                        if (log.isDebugEnabled()) {
                            log.debug("Successfully connected to: {}", socketChannel.getRemoteAddress());
                        }
                        return Optional.ofNullable(socketChannel.getRemoteAddress());
                    }
                } catch (IOException e) {
                    if (log.isDebugEnabled()) {
                        try {
                            log.debug("Error connecting to " + socketChannel.getRemoteAddress(), e);
                        } catch (IOException ex) {
                            log.debug("Error connecting: ", e);
                        }
                    }
                    closeAnyway(socketChannel);
                } finally {
                    iterator.remove();
                }
            }
        }
        return Optional.empty();
    }

    private static void awaitDnsResponses(ConcurrentLinkedQueue<Optional<InetAddress>> resolvedAddressesV6,
                                          ConcurrentLinkedQueue<Optional<InetAddress>> resolvedAddressesV4) {
        final long startTime = System.nanoTime();
        final long sleepDeadline = startTime + TimeUnit.MILLISECONDS.toNanos(100);
        boolean keepGoing = true;
        while (resolvedAddressesV6.isEmpty() && keepGoing) {
            if (!resolvedAddressesV4.isEmpty()) {
                long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(RESOLUTION_DELAY_MILLIS);
                while (haveTime(deadline)) {
                    if (!resolvedAddressesV6.isEmpty()) break;
                }
                keepGoing = false;
            }
            if (!haveTime(sleepDeadline)) {
                try {
                    TimeUnit.MILLISECONDS.sleep(100);
                } catch (InterruptedException ignored) {
                    keepGoing = false;
                }
            }
        }
    }

    private static boolean haveTime(long nanoDeadline) {
        return System.nanoTime() - nanoDeadline < 0;
    }

    private static Runnable dnsLookupRunnable(Name hostname, int queryType, Queue<Optional<InetAddress>> resolvedAddresses) {
        return () -> {
            try {
                final Lookup lookup = new Lookup(hostname, queryType, DClass.IN);
                final Record[] records = lookup.run();
                if (records != null) {
                    for (Record record : records) {
                        InetAddress address = null;
                        if (record instanceof AAAARecord) {
                            address = ((AAAARecord) record).getAddress();
                        } else if (record instanceof ARecord) {
                            address = ((ARecord) record).getAddress();
                        }
                        if (address != null) resolvedAddresses.add(Optional.of(address));
                    }
                }
            } finally {
                resolvedAddresses.add(Optional.empty());
            }
        };
    }

    private static boolean openConnectionFromQueue(Queue<Optional<InetAddress>> queue,
                                                   int port,
                                                   Selector selector) {
        final Optional<InetAddress> addressOptional = queue.poll();
        //noinspection OptionalAssignedToNull
        if (addressOptional != null) {
            if (addressOptional.isPresent()) {
                final InetAddress address = addressOptional.get();
                try {
                    log.info("Connecting to {}", address);
                    final SocketChannel socketChannel = SocketChannel.open();
                    socketChannel.configureBlocking(false);
                    socketChannel.register(selector, SelectionKey.OP_CONNECT);
                    socketChannel.connect(new InetSocketAddress(address, port));
                } catch (IOException e) {
                    // can't connect - move on
                    log.info("Error connecting to {}", address);
                }
            } else {
                return false;
            }
        }
        return true;
    }

    private static void closeAnyway(Closeable closeable) {
        try {
            closeable.close();
        } catch (Exception e) {
            // ignore
        }
    }

    Optional<String> isLiteralIpAddress(String host) {
        if (isLiteralV4Address(host)) return Optional.of(host);
        else if (host.contains(":")) {
            final Matcher matcher = IPV6_ADDRESS_PATTERN.matcher(host);
            if (matcher.matches()) return Optional.of(matcher.group(1));
        }
        return Optional.empty();
    }

    private boolean isLiteralV4Address(String host) {
        return IPV4_ADDRESS_PATTERN.matcher(host).matches();
    }

    private Object joinAddresses(ConcurrentLinkedQueue<Optional<InetAddress>> resolvedAddressesV6) {
        return resolvedAddressesV6.stream()
                .filter(Optional::isPresent)
                .map(Optional::get)
                .map(InetAddress::getHostAddress)
                .collect(Collectors.joining(","));
    }
}

