package com.security.smith.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.security.smith.log.SmithLogger;
import com.security.smith.type.SmithBlock;
import com.security.smith.type.SmithFilter;
import com.security.smith.type.SmithLimit;
import com.security.smith.type.SmithPatch;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.*;
import io.netty.channel.epoll.EpollDomainSocketChannel;
import io.netty.channel.epoll.EpollEventLoopGroup;
import io.netty.channel.unix.DomainSocketAddress;
import io.netty.channel.unix.DomainSocketChannel;
import io.netty.handler.timeout.IdleState;
import io.netty.handler.timeout.IdleStateEvent;
import io.netty.handler.timeout.IdleStateHandler;
import io.netty.util.concurrent.DefaultThreadFactory;

import java.util.concurrent.TimeUnit;

interface ProbeClientHandlerNotify {
    void reconnect();
    void onConnect();
    void onDisconnect();
    void onMessage(ProtocolBuffer protocolBuffer);
}

public class ProbeClient implements ProbeClientHandlerNotify {
    private static final int EVENT_LOOP_THREADS = 1;
    private static final int READ_TIME_OUT = 60;
    private static final int RECONNECT_SCHEDULE = 60;

    private Channel channel;
    private final ProbeNotify probeNotify;
    private final EpollEventLoopGroup group;

    public ProbeClient(ProbeNotify probeNotify) {
        // note: linux use epoll, mac use kqueue
        this.probeNotify = probeNotify;
        this.group = new EpollEventLoopGroup(EVENT_LOOP_THREADS, new DefaultThreadFactory(getClass(), true));
    }

    public void start() {
        SmithLogger.logger.info("probe client start");

        try {
            Bootstrap b = new Bootstrap();
            b.group(group)
                    .channel(EpollDomainSocketChannel.class)
                    .handler(new ChannelInitializer<DomainSocketChannel>() {
                        @Override
                        public void initChannel(DomainSocketChannel ch) {
                            ChannelPipeline p = ch.pipeline();

                            p.addLast(new IdleStateHandler(READ_TIME_OUT, 0, 0, TimeUnit.SECONDS));
                            p.addLast(new ProtocolBufferDecoder());
                            p.addLast(new ProtocolBufferEncoder());
                            p.addLast(new ProbeClientHandler(ProbeClient.this));
                        }
                    });

            channel = b.connect(new DomainSocketAddress("/var/run/smith_agent.sock"))
                    .addListener((ChannelFuture f) -> {
                        if (!f.isSuccess()) {
                            f.channel().eventLoop().schedule(this::reconnect, RECONNECT_SCHEDULE, TimeUnit.SECONDS);
                        }
                    }).sync().channel();

            channel.closeFuture().sync();
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
    }

    public void stop() {
        group.shutdownGracefully();
    }

    public void write(Operate operate, Object object) {
        if (!channel.isActive()) {
            SmithLogger.logger.warning("channel inactive");
            return;
        }

        if (!channel.isWritable()) {
            SmithLogger.logger.warning("channel cannot write");
            return;
        }

        ObjectMapper objectMapper = new ObjectMapper()
                .setPropertyNamingStrategy(PropertyNamingStrategy.SNAKE_CASE);

        ProtocolBuffer protocolBuffer = new ProtocolBuffer();

        protocolBuffer.setOperate(operate);
        protocolBuffer.setData(objectMapper.valueToTree(object));

        channel.writeAndFlush(protocolBuffer);
    }

    @Override
    public void reconnect() {
        SmithLogger.logger.info("reconnect");
        new Thread(this::start).start();
    }

    @Override
    public void onMessage(ProtocolBuffer protocolBuffer) {
        switch (protocolBuffer.getOperate()) {
            case EXIT:
                SmithLogger.logger.info("exit");
                break;

            case HEARTBEAT:
                SmithLogger.logger.info("heartbeat");
                break;

            case CONFIG:
                SmithLogger.logger.info("config");
                probeNotify.onConfig(protocolBuffer.getData().get("config").asText());
                break;

            case CONTROL:
                SmithLogger.logger.info("control");
                probeNotify.onControl(protocolBuffer.getData().get("action").asInt());
                break;

            case DETECT:
                SmithLogger.logger.info("detect");
                probeNotify.onDetect();
                break;

            case FILTER: {
                SmithLogger.logger.info("filter");

                ObjectMapper objectMapper = new ObjectMapper()
                        .setPropertyNamingStrategy(PropertyNamingStrategy.SNAKE_CASE);

                try {
                    probeNotify.onFilter(
                            objectMapper.treeToValue(
                                    protocolBuffer.getData().get("filters"),
                                    SmithFilter[].class
                            )
                    );
                } catch (JsonProcessingException e) {
                    e.printStackTrace();
                }

                break;
            }

            case BLOCK: {
                SmithLogger.logger.info("block");

                ObjectMapper objectMapper = new ObjectMapper()
                        .setPropertyNamingStrategy(PropertyNamingStrategy.SNAKE_CASE);

                try {
                    probeNotify.onBlock(
                            objectMapper.treeToValue(
                                    protocolBuffer.getData().get("blocks"),
                                    SmithBlock[].class
                            )
                    );
                } catch (JsonProcessingException e) {
                    e.printStackTrace();
                }

                break;
            }

            case LIMIT: {
                SmithLogger.logger.info("limit");

                ObjectMapper objectMapper = new ObjectMapper()
                        .setPropertyNamingStrategy(PropertyNamingStrategy.SNAKE_CASE);

                try {
                    probeNotify.onLimit(
                            objectMapper.treeToValue(
                                    protocolBuffer.getData().get("limits"),
                                    SmithLimit[].class
                            )
                    );
                } catch (JsonProcessingException e) {
                    e.printStackTrace();
                }

                break;
            }

            case PATCH: {
                SmithLogger.logger.info("patch");

                ObjectMapper objectMapper = new ObjectMapper()
                        .setPropertyNamingStrategy(PropertyNamingStrategy.SNAKE_CASE);

                try {
                    probeNotify.onPatch(
                            objectMapper.treeToValue(
                                    protocolBuffer.getData().get("patches"),
                                    SmithPatch[].class
                            )
                    );
                } catch (JsonProcessingException e) {
                    e.printStackTrace();
                }

                break;
            }
        }
    }

    @Override
    public void onConnect() {
        probeNotify.onConnect();
    }

    @Override
    public void onDisconnect() {
        probeNotify.onDisconnect();
    }

    static class ProbeClientHandler extends ChannelInboundHandlerAdapter {
        private final ProbeClientHandlerNotify probeClientHandlerNotify;

        ProbeClientHandler(ProbeClientHandlerNotify probeClientHandlerNotify) {
            this.probeClientHandlerNotify = probeClientHandlerNotify;
        }

        @Override
        public void userEventTriggered(ChannelHandlerContext ctx, Object evt) {
            if (evt instanceof IdleStateEvent) {
                IdleStateEvent e = (IdleStateEvent) evt;

                if (e.state() == IdleState.READER_IDLE) {
                    SmithLogger.logger.info("send heartbeat request");

                    ProtocolBuffer protocolBuffer = new ProtocolBuffer();

                    protocolBuffer.setOperate(Operate.HEARTBEAT);
                    ctx.writeAndFlush(protocolBuffer);
                }
            }
        }

        @Override
        public void channelInactive(ChannelHandlerContext ctx) throws Exception {
            super.channelInactive(ctx);

            SmithLogger.logger.info("channel inactive");

            probeClientHandlerNotify.onDisconnect();
            ctx.channel().eventLoop().schedule(probeClientHandlerNotify::reconnect, RECONNECT_SCHEDULE, TimeUnit.SECONDS);
        }

        @Override
        public void channelActive(ChannelHandlerContext ctx) throws Exception {
            super.channelActive(ctx);

            SmithLogger.logger.info("channel active");
            probeClientHandlerNotify.onConnect();
        }

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            probeClientHandlerNotify.onMessage((ProtocolBuffer) msg);
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            probeClientHandlerNotify.onDisconnect();

            SmithLogger.exception(cause);
            ctx.close();
        }
    }
}
