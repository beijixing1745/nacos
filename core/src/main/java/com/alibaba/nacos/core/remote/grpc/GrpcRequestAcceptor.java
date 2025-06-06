/*
 * Copyright 1999-2020 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.alibaba.nacos.core.remote.grpc;

import com.alibaba.nacos.api.exception.NacosException;
import com.alibaba.nacos.api.grpc.auto.Payload;
import com.alibaba.nacos.api.grpc.auto.RequestGrpc;
import com.alibaba.nacos.api.remote.RpcScheduledExecutor;
import com.alibaba.nacos.api.remote.request.Request;
import com.alibaba.nacos.api.remote.request.RequestMeta;
import com.alibaba.nacos.api.remote.request.ServerCheckRequest;
import com.alibaba.nacos.api.remote.response.ErrorResponse;
import com.alibaba.nacos.api.remote.response.Response;
import com.alibaba.nacos.api.remote.response.ResponseCode;
import com.alibaba.nacos.api.remote.response.ServerCheckResponse;
import com.alibaba.nacos.common.constant.HttpHeaderConsts;
import com.alibaba.nacos.common.remote.client.grpc.GrpcUtils;
import com.alibaba.nacos.common.utils.StringUtils;
import com.alibaba.nacos.core.context.RequestContext;
import com.alibaba.nacos.core.context.RequestContextHolder;
import com.alibaba.nacos.core.context.addition.BasicContext;
import com.alibaba.nacos.core.monitor.MetricsMonitor;
import com.alibaba.nacos.core.remote.Connection;
import com.alibaba.nacos.core.remote.ConnectionManager;
import com.alibaba.nacos.core.remote.RequestHandler;
import com.alibaba.nacos.core.remote.RequestHandlerRegistry;
import com.alibaba.nacos.core.utils.Loggers;
import com.alibaba.nacos.sys.utils.ApplicationUtils;
import io.grpc.stub.StreamObserver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

/**
 * rpc request acceptor of grpc.
 *
 * @author liuzunfei
 * @version $Id: GrpcCommonRequestAcceptor.java, v 0.1 2020年09月01日 10:52 AM liuzunfei Exp $
 */
@Service
public class GrpcRequestAcceptor extends RequestGrpc.RequestImplBase {
    
    @Autowired
    RequestHandlerRegistry requestHandlerRegistry;
    
    @Autowired
    private ConnectionManager connectionManager;
    
    private void traceIfNecessary(Payload grpcRequest, boolean receive) {
        String clientIp = grpcRequest.getMetadata().getClientIp();
        String connectionId = GrpcServerConstants.CONTEXT_KEY_CONN_ID.get();
        try {
            if (connectionManager.traced(clientIp)) {
                Loggers.REMOTE_DIGEST.info("[{}] Payload {}, meta={}, body={}", connectionId, receive ? "receive" : "send",
                        grpcRequest.getMetadata().toByteString().toStringUtf8(),
                        grpcRequest.getBody().toByteString().toStringUtf8());
            }
        } catch (Throwable throwable) {
            Loggers.REMOTE_DIGEST.error("[{}] Monitor request error, payload={}, error={}", connectionId, clientIp,
                    grpcRequest.toByteString().toStringUtf8());
        }
        
    }
    
    @Override
    @SuppressWarnings("PMD.MethodTooLongRule")
    public void request(Payload grpcRequest, StreamObserver<Payload> responseObserver) {
        
        traceIfNecessary(grpcRequest, true);
        String type = grpcRequest.getMetadata().getType();
        long startTime = System.nanoTime();
        
        //server is on starting.
        if (!ApplicationUtils.isStarted()) {
            Payload payloadResponse = GrpcUtils.convert(
                    ErrorResponse.build(NacosException.INVALID_SERVER_STATUS, "Server is starting,please try later."));
            traceIfNecessary(payloadResponse, false);
            responseObserver.onNext(payloadResponse);
            
            responseObserver.onCompleted();
            MetricsMonitor.recordGrpcRequestEvent(type, false,
                    NacosException.INVALID_SERVER_STATUS, null, null, System.nanoTime() - startTime);
            return;
        }

        // server check.
        if (ServerCheckRequest.class.getSimpleName().equals(type)) {
            Payload serverCheckResponseP = GrpcUtils.convert(new ServerCheckResponse(GrpcServerConstants.CONTEXT_KEY_CONN_ID.get(), true));
            traceIfNecessary(serverCheckResponseP, false);
            responseObserver.onNext(serverCheckResponseP);
            responseObserver.onCompleted();
            MetricsMonitor.recordGrpcRequestEvent(type, true,
                    0, null, null, System.nanoTime() - startTime);
            return;
        }
        
        RequestHandler requestHandler = requestHandlerRegistry.getByRequestType(type);
        //no handler found.
        if (requestHandler == null) {
            Loggers.REMOTE_DIGEST.warn(String.format("[%s] No handler for request type : %s :", "grpc", type));
            Payload payloadResponse = GrpcUtils
                    .convert(ErrorResponse.build(NacosException.NO_HANDLER, "RequestHandler Not Found"));
            traceIfNecessary(payloadResponse, false);
            responseObserver.onNext(payloadResponse);
            responseObserver.onCompleted();
            MetricsMonitor.recordGrpcRequestEvent(type, false,
                    NacosException.NO_HANDLER, null, null, System.nanoTime() - startTime);
            return;
        }
        
        //check connection status.
        String connectionId = GrpcServerConstants.CONTEXT_KEY_CONN_ID.get();
        boolean requestValid = connectionManager.checkValid(connectionId);
        if (!requestValid) {
            Loggers.REMOTE_DIGEST
                    .warn("[{}] Invalid connection Id ,connection [{}] is un registered ,", "grpc", connectionId);
            Payload payloadResponse = GrpcUtils
                    .convert(ErrorResponse.build(NacosException.UN_REGISTER, "Connection is unregistered."));
            traceIfNecessary(payloadResponse, false);
            responseObserver.onNext(payloadResponse);
            responseObserver.onCompleted();
            MetricsMonitor.recordGrpcRequestEvent(type, false,
                    NacosException.UN_REGISTER, null, null, System.nanoTime() - startTime);
            return;
        }
        
        Object parseObj = null;
        try {
            parseObj = GrpcUtils.parse(grpcRequest);
        } catch (Exception e) {
            Loggers.REMOTE_DIGEST
                    .warn("[{}] Invalid request receive from connection [{}] ,error={}", "grpc", connectionId, e);
            Payload payloadResponse = GrpcUtils.convert(ErrorResponse.build(NacosException.BAD_GATEWAY, e.getMessage()));
            traceIfNecessary(payloadResponse, false);
            responseObserver.onNext(payloadResponse);
            responseObserver.onCompleted();
            MetricsMonitor.recordGrpcRequestEvent(type, false,
                    NacosException.BAD_GATEWAY, e.getClass().getSimpleName(), null, System.nanoTime() - startTime);
            return;
        }
        
        if (parseObj == null) {
            Loggers.REMOTE_DIGEST.warn("[{}] Invalid request receive  ,parse request is null", connectionId);
            Payload payloadResponse = GrpcUtils
                    .convert(ErrorResponse.build(NacosException.BAD_GATEWAY, "Invalid request"));
            traceIfNecessary(payloadResponse, false);
            responseObserver.onNext(payloadResponse);
            responseObserver.onCompleted();

            MetricsMonitor.recordGrpcRequestEvent(type, false,
                    NacosException.BAD_GATEWAY, null, null, System.nanoTime() - startTime);
            return;
        }
        
        if (!(parseObj instanceof Request)) {
            Loggers.REMOTE_DIGEST
                    .warn("[{}] Invalid request receive  ,parsed payload is not a request,parseObj={}", connectionId,
                            parseObj);
            Payload payloadResponse = GrpcUtils
                    .convert(ErrorResponse.build(NacosException.BAD_GATEWAY, "Invalid request"));
            traceIfNecessary(payloadResponse, false);
            responseObserver.onNext(payloadResponse);
            responseObserver.onCompleted();

            MetricsMonitor.recordGrpcRequestEvent(type, false,
                    NacosException.BAD_GATEWAY, null, null, System.nanoTime() - startTime);
            return;
        }
        
        Request request = (Request) parseObj;
        try {
            Connection connection = connectionManager.getConnection(GrpcServerConstants.CONTEXT_KEY_CONN_ID.get());
            RequestMeta requestMeta = new RequestMeta();
            requestMeta.setClientIp(connection.getMetaInfo().getClientIp());
            requestMeta.setConnectionId(GrpcServerConstants.CONTEXT_KEY_CONN_ID.get());
            requestMeta.setClientVersion(connection.getMetaInfo().getVersion());
            requestMeta.setLabels(connection.getMetaInfo().getLabels());
            requestMeta.setAbilityTable(connection.getAbilityTable());
            connectionManager.refreshActiveTime(requestMeta.getConnectionId());
            prepareRequestContext(request, requestMeta, connection);
            Response response = requestHandler.handleRequest(request, requestMeta);
            Payload payloadResponse = GrpcUtils.convert(response);
            traceIfNecessary(payloadResponse, false);
            if (response.getErrorCode() == NacosException.OVER_THRESHOLD) {
                RpcScheduledExecutor.CONTROL_SCHEDULER.schedule(() -> {
                    traceIfNecessary(payloadResponse, false);
                    responseObserver.onNext(payloadResponse);
                    responseObserver.onCompleted();
                }, 1000L, TimeUnit.MILLISECONDS);
            } else {
                traceIfNecessary(payloadResponse, false);
                responseObserver.onNext(payloadResponse);
                responseObserver.onCompleted();
            }
            MetricsMonitor.recordGrpcRequestEvent(type, response.isSuccess(),
                    response.getErrorCode(), null, request.getModule(), System.nanoTime() - startTime);
        } catch (Throwable e) {
            Loggers.REMOTE_DIGEST
                    .error("[{}] Fail to handle request from connection [{}], error message :{}", "grpc", connectionId,
                            e);
            Payload payloadResponse = GrpcUtils.convert(ErrorResponse.build(e));
            traceIfNecessary(payloadResponse, false);
            responseObserver.onNext(payloadResponse);
            responseObserver.onCompleted();
            MetricsMonitor.recordGrpcRequestEvent(type, false,
                    ResponseCode.FAIL.getCode(), e.getClass().getSimpleName(), request.getModule(), System.nanoTime() - startTime);
        } finally {
            RequestContextHolder.removeContext();
        }
        
    }
    
    private void prepareRequestContext(Request request, RequestMeta requestMeta, Connection connection) {
        RequestContext requestContext = RequestContextHolder.getContext();
        requestContext.setRequestId(request.getRequestId());
        requestContext.getBasicContext().setUserAgent(requestMeta.getClientVersion());
        requestContext.getBasicContext().setRequestProtocol(BasicContext.GRPC_PROTOCOL);
        requestContext.getBasicContext().setRequestTarget(request.getClass().getSimpleName());
        String app = connection.getMetaInfo().getAppName();
        if (StringUtils.isBlank(app)) {
            app = request.getHeader(HttpHeaderConsts.APP_FILED, "unknown");
        }
        requestContext.getBasicContext().setApp(app);
        requestContext.getBasicContext().getAddressContext().setRemoteIp(connection.getMetaInfo().getRemoteIp());
        requestContext.getBasicContext().getAddressContext().setRemotePort(connection.getMetaInfo().getRemotePort());
        requestContext.getBasicContext().getAddressContext().setSourceIp(connection.getMetaInfo().getClientIp());
    }
    
}