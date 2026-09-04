package io.fireemu.verification;

import io.grpc.ServerBuilder;
import io.grpc.ServerProvider;
import io.grpc.ServerRegistry;
import io.grpc.netty.NettyServerBuilder;
import java.lang.instrument.Instrumentation;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;

/** Restricts gRPC's port-only server builder to the IPv4 loopback interface. */
public final class LoopbackServerProviderAgent {
    private LoopbackServerProviderAgent() {}

    public static void premain(String ignored, Instrumentation instrumentation) {
        ServerRegistry.getDefaultRegistry().register(new LoopbackServerProvider());
    }

    private static final class LoopbackServerProvider extends ServerProvider {
        @Override
        protected boolean isAvailable() {
            return true;
        }

        @Override
        protected int priority() {
            return 10;
        }

        @Override
        protected ServerBuilder<?> builderForPort(int port) {
            try {
                InetAddress loopback = InetAddress.getByAddress(new byte[] {127, 0, 0, 1});
                return NettyServerBuilder.forAddress(new InetSocketAddress(loopback, port));
            } catch (UnknownHostException impossible) {
                throw new AssertionError(impossible);
            }
        }
    }
}
