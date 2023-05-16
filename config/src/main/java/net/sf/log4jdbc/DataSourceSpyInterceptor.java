/*
 * Copyright 1999-2018 Alibaba Group Holding Ltd.
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

package net.sf.log4jdbc;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;

import java.sql.Connection;

/**
 * DataSourceSpyInterceptor.
 *
 * @author beijixing1745
 */
public class DataSourceSpyInterceptor implements MethodInterceptor {
    /**
     * rdbmsSpecifics.
     */
    private RdbmsSpecifics rdbmsSpecifics = null;

    /**
     * 取得 rdbmsSpecifics.
     *
     * @param conn jdbc链接
     */
    private RdbmsSpecifics getRdbmsSpecifics(Connection conn) {
        if (rdbmsSpecifics == null) {
            rdbmsSpecifics = DriverSpy.getRdbmsSpecifics(conn);
        }
        return rdbmsSpecifics;
    }

    @Override
    public Object invoke(MethodInvocation invocation) throws Throwable {
        Object result = invocation.proceed();
        if (SpyLogFactory.getSpyLogDelegator().isJdbcLoggingEnabled() && result instanceof Connection) {
            Connection conn = (Connection) result;
            return new ConnectionSpy(conn, getRdbmsSpecifics(conn));
        }
        return result;
    }
}
