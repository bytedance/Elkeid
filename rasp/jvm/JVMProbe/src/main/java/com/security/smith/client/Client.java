package com.security.smith.client;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.GsonBuilder;
import com.security.smith.client.message.*;
import com.security.smith.common.ProcessHelper;
import com.security.smith.log.SmithLogger;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.*;
import io.netty.channel.epoll.EpollDomainSocketChannel;
import io.netty.channel.epoll.EpollEventLoopGroup;
import io.netty.channel.unix.DomainSocketAddress;
import io.netty.channel.unix.DomainSocketChannel;
import io.netty.util.concurrent.DefaultThreadFactory;
import io.netty.util.concurrent.GenericFutureListener;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

interface EventHandler {
    void onReconnect();
    void onMessage(Message message);
}

public class Client implements EventHandler {
    private static final int EVENT_LOOP_THREADS = 1;
    private static final int RECONNECT_SCHEDULE = 60;
    private static final String SOCKET_PATH = "/var/run/smith_agent.sock";
    private static final String MESSAGE_DIRECTORY = "/var/run/elkeid_rasp";

    private Channel channel;
    private boolean stopX;
    private MessageHandler messageHandler;
    private EpollEventLoopGroup group;
    private ChannelFuture cf;
    private GenericFutureListener<ChannelFuture> connectListener = (ChannelFuture f) -> {
                        if (!f.isSuccess()) {
                            if(!stopX) {
                                f.channel().eventLoop().schedule(this::onReconnect, RECONNECT_SCHEDULE, TimeUnit.SECONDS);
                            }
                        }
                    };

    public Client(MessageHandler messageHandler) {
        // note: linux use epoll, mac use kqueue
        this.stopX = false;
        this.messageHandler = messageHandler;
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

                            p.addLast(new MessageDecoder());
                            p.addLast(new MessageEncoder());
                            p.addLast(new ClientHandlerAdapter(Client.this));
                        }
                    });

            cf = b.connect(new DomainSocketAddress(SOCKET_PATH)).addListener(connectListener);

            channel = cf.sync().channel();

            channel.closeFuture().sync();
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
    }

    public void stop() {
        stopX = true;
        group.shutdownGracefully();
        messageHandler = null;
        group = null;
        channel.close();
        channel = null;
        cf.removeListener(connectListener);
        cf = null;
        connectListener = null;
    }

    public void write(int operate, Object object) {
        if (channel == null || !channel.isActive() || !channel.isWritable())
            return;

        try {
            //TODO must send metadata first
            if (operate == Operate.CLASSUPLOAD) {
                Thread.sleep(1000);
            }
        } catch (Exception e) {
            
        }

        Message message = new Message();
        message.setOperate(operate);

        message.setData((JsonElement)object);

        channel.writeAndFlush(message);
    }

    @Override
    public void onReconnect() {
        SmithLogger.logger.info("reconnect");

        readMessage();
        new Thread(this::start).start();
    }

    @Override
    public void onMessage(Message message) {
        switch (message.getOperate()) {
            case Operate.EXIT:
                SmithLogger.logger.info("exit");
                break;

            case Operate.HEARTBEAT:
                SmithLogger.logger.info("heartbeat");
                break;

            case Operate.CONFIG:
                SmithLogger.logger.info("config");
                JsonElement configElement = message.getData().getAsJsonObject().get("config");
                if (configElement != null && configElement.isJsonPrimitive()) {
                    String config = configElement.getAsString();
                    messageHandler.onConfig(config);
                } 
                break;

            case Operate.CONTROL:
                SmithLogger.logger.info("control");
                JsonElement actionElement = message.getData().getAsJsonObject().get("action");
                if (actionElement != null && actionElement.isJsonPrimitive() && actionElement.getAsJsonPrimitive().isNumber()) {
                    int action = actionElement.getAsInt();
                    messageHandler.onControl(action);
                } 
                break;

            case Operate.DETECT:
                SmithLogger.logger.info("detect");
                messageHandler.onDetect();
                break;

            case Operate.FILTER: {
                SmithLogger.logger.info("filter: " + message.getData().toString());

                try {
                    Gson gson = new Gson();
                    FilterConfig config = gson.fromJson(message.getData().toString(), FilterConfig.class);
                    messageHandler.onFilter(config);
                } catch (Exception e) {
                    SmithLogger.exception(e);
                }

                break;
            }

            case Operate.BLOCK: {
                SmithLogger.logger.info("block: " + message.getData().toString());

                try {
                    Gson gson = new Gson();
                    BlockConfig config = gson.fromJson(message.getData().toString(), BlockConfig.class);
                    messageHandler.onBlock(config);
                } catch (Exception e) {
                    SmithLogger.exception(e);
                }

                break;
            }

            case Operate.LIMIT: {
                SmithLogger.logger.info("limit: " + message.getData().toString());

                try {
                    Gson gson = new Gson();
                    LimitConfig config = gson.fromJson(message.getData().toString(), LimitConfig.class);
                    messageHandler.onLimit(config);
                } catch (Exception e) {
                    SmithLogger.exception(e);
                }

                break;
            }

            case Operate.PATCH: {
                SmithLogger.logger.info("patch: " + message.getData().toString());

                try {
                    Gson gson = new Gson();
                    PatchConfig config = gson.fromJson(message.getData().toString(), PatchConfig.class);
                    messageHandler.onPatch(config);
                } catch (Exception e) {
                    SmithLogger.exception(e);
                }

                break;
            }
            case Operate.CLASSFILTERSTART: {
                 SmithLogger.logger.info("rule upload start: " + message.getData().toString());

                try {
                    Gson gson = new Gson();
                    Rule_Version ruleVersion = gson.fromJson(message.getData().toString(), Rule_Version.class);
                    messageHandler.setRuleVersion(ruleVersion);
                } catch (Exception e) {
                    SmithLogger.exception(e);
                }

                break;
            }
            case Operate.CLASSFILTER: {
                 SmithLogger.logger.info("rule upload: " + message.getData().toString());

                try {
                    Gson gson = new Gson();
                    Rule_Data ruleData = gson.fromJson(message.getData().toString(), Rule_Data.class);
                    messageHandler.OnAddRule(ruleData);
                } catch (Exception e) {
                    SmithLogger.exception(e);
                }

                break;
            }
            case Operate.CLASSFILTEREND: {
                SmithLogger.logger.info("class filter config receive finish, start to scan all class");
                Thread scanAllClassThread = new Thread(messageHandler::onScanAllClass);
                scanAllClassThread.setDaemon(true);
                scanAllClassThread.start();
                break;
            }
            case Operate.SWITCHES: {
                SmithLogger.logger.info("switches: " + message.getData().toString());

                try {
                    Gson gson = new Gson();
                    SwitchConfig config = gson.fromJson(message.getData().toString(), SwitchConfig.class);
                    messageHandler.onSwitches(config);
                } catch (Exception e) {
                    SmithLogger.exception(e);
                }

                break;
            }
        }
    }

    private void readMessage() {
        Path path = Paths.get(MESSAGE_DIRECTORY, String.format("%d.json", ProcessHelper.getCurrentPID()));

        if (!Files.exists(path)) {
            SmithLogger.logger.info("message file not exist: " + path);
            return;
        }

        SmithLogger.logger.info("read message file: " + path);

        try {
             String json = Files.lines(path, StandardCharsets.UTF_8)
                .collect(Collectors.joining("\n"));
            JsonElement jsonElement = JsonParser.parseString(json);
            
            if (jsonElement.isJsonArray()) {
                JsonArray jsonArray = jsonElement.getAsJsonArray();
                for (JsonElement element : jsonArray) {
                    if (element.isJsonObject()) {
                        Gson gson = new GsonBuilder().registerTypeAdapter(Message.class, new MessageDeserializer()).create();
                        Message message = gson.fromJson(element, Message.class);
                        onMessage(message);
                    }
                }
            }

            Files.delete(path);
        } catch (IOException e) {
            SmithLogger.exception(e);
        }
    }

    static class ClientHandlerAdapter extends ChannelInboundHandlerAdapter {
        private EventHandler eventHandler;

        ClientHandlerAdapter(EventHandler eventHandler) {
            this.eventHandler = eventHandler;
        }

        public void closeHandler() {
            this.eventHandler = null;
        }

        @Override
        public void channelInactive(ChannelHandlerContext ctx) throws Exception {
            super.channelInactive(ctx);
            SmithLogger.logger.info("channel inactive");

            ctx.channel().eventLoop().schedule(
                    eventHandler::onReconnect,
                    RECONNECT_SCHEDULE,
                    TimeUnit.SECONDS
            );
        }

        @Override
        public void channelActive(ChannelHandlerContext ctx) throws Exception {
            super.channelActive(ctx);
            SmithLogger.logger.info("channel active");
        }

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            eventHandler.onMessage((Message) msg);
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            SmithLogger.exception(cause);
            ctx.close();
        }
    }
}
