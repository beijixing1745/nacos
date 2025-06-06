@echo off
rem Copyright 1999-2018 Alibaba Group Holding Ltd.
rem Licensed under the Apache License, Version 2.0 (the "License");
rem you may not use this file except in compliance with the License.
rem You may obtain a copy of the License at
rem
rem      http://www.apache.org/licenses/LICENSE-2.0
rem
rem Unless required by applicable law or agreed to in writing, software
rem distributed under the License is distributed on an "AS IS" BASIS,
rem WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
rem See the License for the specific language governing permissions and
rem limitations under the License.
if not exist "%JAVA_HOME%\bin\java.exe" echo Please set the JAVA_HOME variable in your environment, We need java(x64)! jdk8 or later is better! & EXIT /B 1
set "JAVA=%JAVA_HOME%\bin\java.exe"

setlocal enabledelayedexpansion

set BASE_DIR=%~dp0
rem added double quotation marks to avoid the issue caused by the folder names containing spaces.
rem removed the last 5 chars(which means \bin\) to get the base DIR.
set BASE_DIR="%BASE_DIR:~0,-5%"

set CUSTOM_SEARCH_LOCATIONS=file:%BASE_DIR%/conf/

set MODE="cluster"
set FUNCTION_MODE="all"
set SERVER=nacos-server
set MODE_INDEX=-1
set FUNCTION_MODE_INDEX=-1
set SERVER_INDEX=-1
set EMBEDDED_STORAGE_INDEX=-1
set EMBEDDED_STORAGE=""
set DEPLOYMENT_INDEX=-1
set DEPLOYMENT="merged"

set i=0
for %%a in (%*) do (
    if "%%a" == "-m" ( set /a MODE_INDEX=!i!+1 )
    if "%%a" == "-f" ( set /a FUNCTION_MODE_INDEX=!i!+1 )
    if "%%a" == "-s" ( set /a SERVER_INDEX=!i!+1 )
    if "%%a" == "-p" ( set /a EMBEDDED_STORAGE_INDEX=!i!+1 )
    if "%%a" == "-d" ( set /a DEPLOYMENT_INDEX=!i!+1 )
    set /a i+=1
)

set i=0
for %%a in (%*) do (
    if %MODE_INDEX% == !i! ( set MODE="%%a" )
    if %FUNCTION_MODE_INDEX% == !i! ( set FUNCTION_MODE="%%a" )
    if %SERVER_INDEX% == !i! (set SERVER="%%a")
    if %EMBEDDED_STORAGE_INDEX% == !i! (set EMBEDDED_STORAGE="%%a")
    if %DEPLOYMENT_INDEX% == !i! (set DEPLOYMENT="%%a")
    set /a i+=1
)

call :Process_required_config "nacos.core.auth.plugin.nacos.token.secret.key" %BASE_DIR%\conf\application.properties
call :Process_required_config "nacos.core.auth.server.identity.key" %BASE_DIR%\conf\application.properties
call :Process_required_config "nacos.core.auth.server.identity.value" %BASE_DIR%\conf\application.properties

rem if nacos startup mode is standalone
if %MODE% == "standalone" (
    echo "nacos is starting with standalone"
	  set "NACOS_OPTS=-Dnacos.standalone=true"
    if "%CUSTOM_NACOS_MEMORY%"=="" ( set "CUSTOM_NACOS_MEMORY=-Xms512m -Xmx512m -Xmn256m" )
    set "NACOS_JVM_OPTS=%CUSTOM_NACOS_MEMORY%"
)

rem if nacos startup mode is cluster
if %MODE% == "cluster" (
    echo "nacos is starting with cluster"
	  if %EMBEDDED_STORAGE% == "embedded" (
	      set "NACOS_OPTS=-DembeddedStorage=true"
	  )
    if "%CUSTOM_NACOS_MEMORY%"=="" ( set "CUSTOM_NACOS_MEMORY=-Xms2g -Xmx2g -Xmn1g -XX:MetaspaceSize=128m -XX:MaxMetaspaceSize=320m" )
    set "NACOS_JVM_OPTS=-server %CUSTOM_NACOS_MEMORY% -XX:-OmitStackTraceInFastThrow -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=%BASE_DIR%\logs\java_heapdump.hprof -XX:-UseLargePages"
)

rem set nacos's functionMode
if %FUNCTION_MODE% == "config" (
    set "NACOS_OPTS=%NACOS_OPTS% -Dnacos.functionMode=config"
)

if %FUNCTION_MODE% == "naming" (
    set "NACOS_OPTS=%NACOS_OPTS% -Dnacos.functionMode=naming"
)

rem set nacos options
set "NACOS_OPTS=%NACOS_OPTS% -Dnacos.deployment.mode=%DEPLOYMENT%"
set "NACOS_OPTS=%NACOS_OPTS% -Dloader.path=%BASE_DIR%/plugins,%BASE_DIR%/plugins/health,%BASE_DIR%/plugins/cmdb,%BASE_DIR%/plugins/selector"
set "NACOS_OPTS=%NACOS_OPTS% -Dnacos.home=%BASE_DIR%"
set "NACOS_OPTS=%NACOS_OPTS% -jar %BASE_DIR%\target\%SERVER%.jar"

rem set nacos spring config location
set "NACOS_CONFIG_OPTS=--spring.config.additional-location=%CUSTOM_SEARCH_LOCATIONS%"

rem set nacos log4j file location
set "NACOS_LOG4J_OPTS=--logging.config=%BASE_DIR%/conf/nacos-logback.xml"


set COMMAND="%JAVA%" %NACOS_JVM_OPTS% %NACOS_OPTS% %NACOS_CONFIG_OPTS% %NACOS_LOG4J_OPTS% nacos.nacos %*

rem start nacos command
%COMMAND%

pause

goto :EOF

:Process_required_config
    setlocal
    set "key_pattern=%~1"
    set "target_file=%~2"
    set "target_file=!target_file:"=!"

    set "escaped_key=%key_pattern:.=\.%"

    findstr /R /C:"^%escaped_key%[= ].*" "%target_file%" >nul
    if %errorlevel% == 0 (
        rem Check if the value of the key is empty
        for /f "usebackq tokens=1,2 delims==" %%a in ("%target_file%") do (
            if "%%a"=="%key_pattern%" if "%%b"=="" (
                rem Value is empty, request input from user
                set /p "input_val=%key_pattern% value is empty, please input: "
                set "temp_file=%TEMP%\temp_%RANDOM%.tmp"
                set "key_pattern_with_equal=!key_pattern!="

                for /f "usebackq delims=" %%a in ("!target_file!") do (
                    set "line=%%a"
                    set "line=!line: =!"
                    if "!line!"=="!key_pattern_with_equal!" (
                        echo %%a!input_val!>>"!temp_file!"
                    ) else (
                        echo %%a>>"!temp_file!"
                    )
                )
                move /Y "!temp_file!" "!target_file!" >nul
                echo %key_pattern% Updated with new value:%input_val%
                findstr /R "^%escaped_key%" "%target_file%"
                echo ----------------------------------
                exit /b
            )
        )
    )
    endlocal
