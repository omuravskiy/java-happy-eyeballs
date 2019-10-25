import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Type;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

public class HappyEyeballs {

    // delays from RFC8305/Section 8
    private static final long RESOLUTION_DELAY_MILLIS = 50L;
    private static final long CONNECTION_ATTEMPT_DELAY_MS = 250L;
    private static Logger logger = LoggerFactory.getLogger(HappyEyeballs.class);
    private ExecutorService executor = Executors.newCachedThreadPool();

    public Future<List<SocketAddress>> resolveAsync(String host, int port) {
        return executor.submit(() -> {
            final Name hostname = Name.fromString(host);
            List<SocketAddress> bestAddress;

            final ConcurrentLinkedQueue<Optional<InetAddress>> resolvedAddressesV6 = new ConcurrentLinkedQueue<>();
            final Thread v6thread = new Thread(dnsLookupRunnable(hostname, Type.AAAA, resolvedAddressesV6));
            v6thread.start();

            final ConcurrentLinkedQueue<Optional<InetAddress>> resolvedAddressesV4 = new ConcurrentLinkedQueue<>();
            final Thread v4thread = new Thread(dnsLookupRunnable(hostname, Type.A, resolvedAddressesV4));
            v4thread.start();

            awaitDnsResponses(resolvedAddressesV6, resolvedAddressesV4);

            if (logger.isDebugEnabled()) {
                logger.debug(
                        "Resolved v6 addresses: {}",
                        joinAddresses(resolvedAddressesV6));
                logger.debug(
                        "Resolved v4 addresses: {}",
                        joinAddresses(resolvedAddressesV4));
            }

            final ConcurrentLinkedQueue<Optional<SocketChannel>> sockets = new ConcurrentLinkedQueue<>();
            final Thread connectionsThread =
                    new Thread(connectAttemptsRunnable(resolvedAddressesV6, resolvedAddressesV4, sockets, port));
            connectionsThread.start();

            bestAddress = awaitSuccessfulConnection(sockets);

            executor.execute(() -> {
                connectionsThread.interrupt();
                v6thread.interrupt();
                v4thread.interrupt();
                for (Optional<SocketChannel> channelOptional : sockets) {
                    channelOptional.ifPresent(channel -> {
                        try {
                            channel.close();
                        } catch (Exception e) {
                            // ignore
                        }
                    });
                }
            });

            return bestAddress;
        });
    }

    private static List<SocketAddress> awaitSuccessfulConnection(ConcurrentLinkedQueue<Optional<SocketChannel>> sockets)
            throws IOException {
        final ArrayList<SocketAddress> result = new ArrayList<>();
        boolean keepGoing = true;
        while (keepGoing) {
            final Iterator<Optional<SocketChannel>> iterator = sockets.iterator();
            int count = 0;
            while (iterator.hasNext()) {
                count++;
                final Optional<SocketChannel> socketChannelOptional = iterator.next();
                if (socketChannelOptional.isPresent()) {
                    final SocketChannel socketChannel = socketChannelOptional.get();
                    try {
                        if (socketChannel.finishConnect()) {
                            if (logger.isDebugEnabled()) {
                                logger.debug("Successfully connected to: {}", socketChannel.getRemoteAddress());
                            }
                            keepGoing = false;
                            result.add(socketChannel.getRemoteAddress());
                        }
                    } catch (IOException e) {
                        if (logger.isDebugEnabled()) {
                            logger.debug("Error connecting to " + socketChannel.getRemoteAddress(), e);
                        }
                        iterator.remove();
                    }
                } else {
                    if (count == 1) {
                        keepGoing = false;
                    }
                    break;
                }
            }
        }
        return result;
    }

    private static void awaitDnsResponses(ConcurrentLinkedQueue<Optional<InetAddress>> resolvedAddressesV6,
                                          ConcurrentLinkedQueue<Optional<InetAddress>> resolvedAddressesV4) {
        boolean keepGoing = true;
        while (resolvedAddressesV6.isEmpty() && keepGoing) {
            if (!resolvedAddressesV4.isEmpty()) {
                long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(RESOLUTION_DELAY_MILLIS);
                while (haveTime(deadline)) {
                    if (!resolvedAddressesV6.isEmpty()) break;
                }
                keepGoing = false;
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

    private static Runnable connectAttemptsRunnable(Queue<Optional<InetAddress>> firstAfAddresses,
                                                    Queue<Optional<InetAddress>> secondAfAddresses,
                                                    Queue<Optional<SocketChannel>> socketChannels,
                                                    final int port) {
        return new Runnable() {
            @Override
            public void run() {
                try {
                    boolean keepGoing = true;
                    while (keepGoing && !Thread.currentThread().isInterrupted()) {
                        final boolean haveMoreAF1 = openConnectionFromQueue(firstAfAddresses);
                        final boolean haveMoreAF2 = openConnectionFromQueue(secondAfAddresses);
                        // watch out! do not inline these booleans,
                        // otherwise you'll shortcircuit second evaluation
                        keepGoing = haveMoreAF1 || haveMoreAF2;
                    }
                } catch (InterruptedException e) {
                    // just stop
                } finally {
                    socketChannels.add(Optional.empty());
                }
            }

            private boolean openConnectionFromQueue(Queue<Optional<InetAddress>> queue) throws InterruptedException {
                final Optional<InetAddress> addressOptional = queue.poll();
                if (addressOptional != null) {
                    if (addressOptional.isPresent()) {
                        final InetAddress address = addressOptional.get();
                        try {
                            logger.debug("Connecting to {}", address);
                            final SocketChannel socketChannel = SocketChannel.open();
                            socketChannel.configureBlocking(false);
                            socketChannel.connect(new InetSocketAddress(address, port));
                            socketChannels.add(Optional.of(socketChannel));
                        } catch (IOException e) {
                            // can't connect - move on
                            logger.debug("Error connecting to {}", address);
                        } finally {
                            TimeUnit.MILLISECONDS.sleep(CONNECTION_ATTEMPT_DELAY_MS);
                        }
                    } else {
                        return false;
                    }
                }
                return true;
            }
        };
    }

    private Object joinAddresses(ConcurrentLinkedQueue<Optional<InetAddress>> resolvedAddressesV6) {
        return resolvedAddressesV6.stream()
                                  .filter(Optional::isPresent)
                                  .map(Optional::get)
                                  .map(InetAddress::getHostAddress)
                                  .collect(Collectors.joining(","));
    }
}

