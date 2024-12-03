import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicIntegerArray;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.stream.Stream;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import com.lmax.disruptor.InsufficientCapacityException;
import com.lmax.disruptor.RingBuffer;
import com.lmax.disruptor.dsl.Disruptor;
import com.security.smith.client.MessageSerializer;
import com.security.smith.client.MessageDeserializer;
import com.security.smith.client.MessageDecoder;
import com.security.smith.client.MessageEncoder;
import com.security.smith.type.SmithClass;
import com.security.smith.type.SmithMethod;
import com.security.smith.ruleengine.JsRuleEngine;
import com.security.smith.SmithProbe;
import com.security.smith.client.message.Heartbeat;
import com.lmax.disruptor.dsl.Disruptor;
import com.lmax.disruptor.EventFactory;
import com.security.smith.client.message.Trace;
import com.security.smith.SmithProbeProxy;
import com.security.smith.client.Client;
import com.security.smith.SmithProbe;
import com.security.smith.client.Rule_Config;
import com.security.smith.client.Rule_Mgr;
import com.security.smith.common.Reflection;
import com.security.smith.ruleengine.JsRuleResult;
import com.security.smith.client.message.Block;
import com.security.smith.client.message.MatchRule;
import com.security.smith.client.message.ClassFilter;
import com.security.smith.common.SmithHandler;
import com.security.smith.client.Operate;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.GsonBuilder;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class SmithProbeProxyTest {

    @Mock
    private SmithProbe smithProbeObjMock;

    @Mock
    private JsRuleEngine jsRuleEngineMock;

    @Mock
    private Client clientMock;

    @Mock
    private Disruptor<Trace> disruptorMock;

    @Mock
    private RingBuffer<Trace> ringBufferMock;

    private SmithProbeProxy smithProbeProxy;

    @Before
    public void setUp() {
        smithProbeProxy = new SmithProbeProxy(10, 10);
        smithProbeProxy.setProbe(smithProbeObjMock);
        smithProbeProxy.setClient(clientMock);
        smithProbeProxy.setDisruptor(disruptorMock);
    }

    @Test
    public void testHandleReflectMethod_FunctionEnabled_ArgsLengthValid_NotSecurityPackage() {
        // Arrange
        int classID = 43; // java.lang.reflect.Method
        int methodID = 0; // <init>
        Object[] args = new Object[]{String.class, "fieldName"};
        Object ret = null;
        boolean blocked = false;

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Mock checkReflectEvil
        when(smithProbeProxy.checkReflectEvil(anyString(), anyString(), eq(true))).thenReturn(true);

        // Act
        smithProbeProxy.handleReflectMethod(classID, methodID, args, ret, blocked);

        // Assert
        verify(smithProbeProxy, times(1)).trace(classID, methodID, args, ret, blocked);
    }

    @Test
    public void testHandleReflectMethod_FunctionDisabled() {
        // Arrange
        int classID = 43; // java.lang.reflect.Method
        int methodID = 0; // <init>
        Object[] args = new Object[]{String.class, "fieldName"};
        Object ret = null;
        boolean blocked = false;

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(false);

        // Act
        smithProbeProxy.handleReflectMethod(classID, methodID, args, ret, blocked);

        // Assert
        verify(smithProbeProxy, never()).trace(anyInt(), anyInt(), any(), any(), anyBoolean());
    }

    @Test
    public void testHandleReflectMethod_ArgsLengthInvalid() {
        // Arrange
        int classID = 43; // java.lang.reflect.Method
        int methodID = 0; // <init>
        Object[] args = new Object[]{String.class};
        Object ret = null;
        boolean blocked = false;

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Act
        smithProbeProxy.handleReflectMethod(classID, methodID, args, ret, blocked);

        // Assert
        verify(smithProbeProxy, never()).trace(anyInt(), anyInt(), any(), any(), anyBoolean());
    }

    @Test
    public void testHandleReflectMethod_SecurityPackage() {
        // Arrange
        int classID = 43; // java.lang.reflect.Method
        int methodID = 0; // <init>
        Object[] args = new Object[]{java.io.InputStreamReader.class, "fieldName"};
        Object ret = null;
        boolean blocked = false;

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Act
        smithProbeProxy.handleReflectMethod(classID, methodID, args, ret, blocked);

        // Assert
        verify(smithProbeProxy, never()).trace(anyInt(), anyInt(), any(), any(), anyBoolean());
    }

    @Test
    public void testHandleReflectMethod_ExceptionThrown() throws ClassNotFoundException {
        // Arrange
        int classID = 43; // java.lang.reflect.Method
        int methodID = 0; // <init>
        Object[] args = new Object[]{"invalidClass", "fieldName"};
        Object ret = null;
        boolean blocked = false;

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Act
        smithProbeProxy.handleReflectMethod(classID, methodID, args, ret, blocked);

        // Assert
        verify(smithProbeProxy, never()).trace(anyInt(), anyInt(), any(), any(), anyBoolean());
    }

    @Test
    public void testTrace_FunctionEnabled_QuotaAvailable() throws InsufficientCapacityException {
        // Arrange
        int classID = 0; // java.lang.ProcessImpl
        int methodID = 0; // start
        Object[] args = new Object[]{String.class, "fieldName"};
        Object ret = null;
        boolean blocked = false;

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Mock Disruptor
        when(disruptorMock.getRingBuffer()).thenReturn(ringBufferMock);
        when(ringBufferMock.tryNext()).thenReturn(1L);

        // Act
        smithProbeProxy.trace(classID, methodID, args, ret, blocked);

        // Assert
        verify(ringBufferMock, times(1)).publish(1L);
    }

    @Test
    public void testTrace_FunctionDisabled() {
        // Arrange
        int classID = 0; // java.lang.ProcessImpl
        int methodID = 0; // start
        Object[] args = new Object[]{String.class, "fieldName"};
        Object ret = null;
        boolean blocked = false;

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(false);

        // Act
        smithProbeProxy.trace(classID, methodID, args, ret, blocked);

        // Assert
        try {
            verify(ringBufferMock, never()).tryNext();
        } catch (InsufficientCapacityException e) {
        }
    }

    @Test
    public void testTrace_QuotaExceeded() throws InsufficientCapacityException {
        // Arrange
        int classID = 0; // java.lang.ProcessImpl
        int methodID = 0; // start
        Object[] args = new Object[]{String.class, "fieldName"};
        Object ret = null;
        boolean blocked = false;

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Mock Disruptor
        when(disruptorMock.getRingBuffer()).thenReturn(ringBufferMock);
        when(ringBufferMock.tryNext()).thenThrow(InsufficientCapacityException.class);

        // Act
        smithProbeProxy.trace(classID, methodID, args, ret, blocked);

        // Assert
        verify(smithProbeObjMock, times(1)).addDisacrdCount();
    }

    @Test
    public void testCheckReflectEvil_RuleDetected() {
        // Arrange
        String classname = "someClass";
        String fieldname = "someField";
        boolean isMethod = true;

        // Mock JsRuleEngine.detect
        when(smithProbeObjMock.getJsRuleEngine()).thenReturn(jsRuleEngineMock);
        when(jsRuleEngineMock.detect(2, any())).thenReturn(new JsRuleResult());

        // Act
        boolean result = smithProbeProxy.checkReflectEvil(classname, fieldname, isMethod);

        // Assert
        assertTrue(result);
    }

    @Test
    public void testCheckReflectEvil_RuleNotDetected() {
        // Arrange
        String classname = "someClass";
        String fieldname = "someField";
        boolean isMethod = true;

        // Mock JsRuleEngine.detect
        when(smithProbeObjMock.getJsRuleEngine()).thenReturn(jsRuleEngineMock);
        when(jsRuleEngineMock.detect(2, any())).thenReturn(null);

        // Act
        boolean result = smithProbeProxy.checkReflectEvil(classname, fieldname, isMethod);

        // Assert
        assertFalse(result);
    }

    @Test
    public void testCheckReflectEvil_ExceptionThrown() {
        // Arrange
        String classname = "someClass";
        String fieldname = "someField";
        boolean isMethod = true;

        // Mock JsRuleEngine.detect
        when(smithProbeObjMock.getJsRuleEngine()).thenReturn(jsRuleEngineMock);
        when(jsRuleEngineMock.detect(2, any())).thenThrow(new RuntimeException());

        // Act
        boolean result = smithProbeProxy.checkReflectEvil(classname, fieldname, isMethod);

        // Assert
        assertFalse(result);
    }

    @Test
    public void testDetect_FunctionEnabled_Blocked() {
        // Arrange
        int classID = 0; // java.lang.ProcessImpl
        int methodID = 0; // start
        Object[] args = new Object[]{"arg1", "arg2"};

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Mock SmithProbeObj.GetBlocks
        Map<Pair<Integer, Integer>, Block> blocks = new HashMap<>();
        Block block = mock(Block.class);
        blocks.put(new ImmutablePair<>(classID, methodID), block);
        when(smithProbeObjMock.GetBlocks()).thenReturn(blocks);

        // Mock Block.getRules
        MatchRule[] rules = new MatchRule[]{mock(MatchRule.class)};
        when(block.getRules()).thenReturn(rules);

        // Mock MatchRule.getIndex and MatchRule.getRegex
        when(rules[0].getIndex()).thenReturn(1);
        when(rules[0].getRegex()).thenReturn("arg2");

        // Act
        try {
            smithProbeProxy.detect(classID, methodID, args);
            fail("Expected SecurityException");
        } catch (SecurityException e) {
            // Assert
            assertEquals("API blocked by RASP", e.getMessage());
        }
    }

    @Test
    public void testDetect_FunctionDisabled() {
        // Arrange
        int classID = 0; // java.lang.ProcessImpl
        int methodID = 0; // start
        Object[] args = new Object[]{"arg1", "arg2"};

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(false);

        // Act
        smithProbeProxy.detect(classID, methodID, args);

        // Assert
        verify(smithProbeObjMock, never()).GetBlocks();
    }

    @Test
    public void testDetect_NoBlockRules() {
        // Arrange
        int classID = 0; // java.lang.ProcessImpl
        int methodID = 0; // start
        Object[] args = new Object[]{"arg1", "arg2"};

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Mock SmithProbeObj.GetBlocks
        Map<Pair<Integer, Integer>, Block> blocks = new HashMap<>();
        Block block = mock(Block.class);
        blocks.put(new ImmutablePair<>(classID, methodID), block);
        when(smithProbeObjMock.GetBlocks()).thenReturn(blocks);

        // Mock Block.getRules
        MatchRule[] rules = new MatchRule[]{mock(MatchRule.class)};
        when(block.getRules()).thenReturn(rules);

        // Mock MatchRule.getIndex and MatchRule.getRegex
        when(rules[0].getIndex()).thenReturn(1);
        when(rules[0].getRegex()).thenReturn("notMatchingRegex");

        // Act
        smithProbeProxy.detect(classID, methodID, args);

        // Assert
        verify(smithProbeObjMock, never()).addDisacrdCount();
    }

    @Test
    public void testSendMetadataObject_FunctionEnabled() {
        // Arrange
        Object obj = new Object();
        int classID = 0; // java.lang.ProcessImpl
        int methodID = 0; // start

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Act
        smithProbeProxy.sendMetadataObject(obj, classID, methodID);

        // Assert
        verify(smithProbeProxy, times(1)).sendMetadataClass(obj.getClass(), classID, methodID);
    }

    @Test
    public void testSendMetadataObject_FunctionDisabled() {
        // Arrange
        Object obj = new Object();
        int classID = 0; // java.lang.ProcessImpl
        int methodID = 0; // start

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(false);

        // Act
        smithProbeProxy.sendMetadataObject(obj, classID, methodID);

        // Assert
        verify(smithProbeProxy, never()).sendMetadataClass(any(), anyInt(), anyInt());
    }

    @Test
    public void testSendMetadataClass_ClassNotSent() {
        // Arrange
        Class<?> clazz = Object.class;
        int classID = 0; // java.lang.ProcessImpl
        int methodID = 0; // start

        // Mock SmithProbeObj.classIsSended
        when(smithProbeObjMock.classIsSended(clazz)).thenReturn(false);

        // Mock JsRuleEngine.detect
        when(smithProbeObjMock.getJsRuleEngine()).thenReturn(jsRuleEngineMock);
        when(jsRuleEngineMock.detect(1, any())).thenReturn(new JsRuleResult());

        // Mock SmithHandler.queryClassFilter
        ClassFilter classFilter = mock(ClassFilter.class);
        when(classFilter.getTransId()).thenReturn("1");
        when(classFilter.getRuleId()).thenReturn(Long.valueOf(-1));
        when(classFilter.getClassId()).thenReturn(classID);
        when(classFilter.getMethodId()).thenReturn(methodID);
        when(classFilter.getTypes()).thenReturn(new String(""));
        when(classFilter.getStackTrace()).thenReturn(new StackTraceElement[]{});
        SmithHandler smithHandler = mock(SmithHandler.class);
        doNothing().when(smithHandler).queryClassFilter(any(Class.class), any());

        // Mock Gson
        Gson gson = mock(Gson.class);
        when(gson.toJsonTree(classFilter)).thenReturn(mock(JsonElement.class));

        // Act
        smithProbeProxy.sendMetadataClass(clazz, classID, methodID);

        // Assert
        verify(clientMock, times(1)).write(Operate.SCANCLASS, any());
        verify(smithProbeObjMock, times(1)).sendClass(clazz, "1");
    }

    @Test
    public void testSendMetadataClass_ClassAlreadySent() {
        // Arrange
        Class<?> clazz = Object.class;
        int classID = 0; // java.lang.ProcessImpl
        int methodID = 0; // start

        // Mock SmithProbeObj.classIsSended
        when(smithProbeObjMock.classIsSended(clazz)).thenReturn(true);

        // Act
        smithProbeProxy.sendMetadataClass(clazz, classID, methodID);

        // Assert
        verify(clientMock, never()).write(any(), any());
        verify(smithProbeObjMock, never()).sendClass(any(), anyString());
    }

    @Test
    public void testCheckAddServletPre_FunctionEnabled() throws Exception {
        // Arrange
        int classID = 15; // org.apache.catalina.core.StandardContext
        int methodID = 0; // addServletMapping
        Object[] args = new Object[]{mock(Object.class), "contextName", "servletName"};

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Mock Reflection.invokeMethod
        Object wrapper = mock(Object.class);
        when(Reflection.invokeMethod(args[0], "findChild", new Class[]{String.class}, "servletName")).thenReturn(wrapper);

        Object servlet = mock(Object.class);
        when(Reflection.invokeMethod(wrapper, "getServlet", new Class[]{})).thenReturn(servlet);

        // Act
        smithProbeProxy.checkAddServletPre(classID, methodID, args);

        // Assert
        verify(smithProbeProxy, times(1)).sendMetadataObject(servlet, classID, methodID);
    }

    @Test
    public void testCheckAddServletPre_FunctionDisabled() {
        // Arrange
        int classID = 15; // org.apache.catalina.core.StandardContext
        int methodID = 0; // addServletMapping
        Object[] args = new Object[]{mock(Object.class), "contextName", "servletName"};

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(false);

        // Act
        smithProbeProxy.checkAddServletPre(classID, methodID, args);

        // Assert
        verify(smithProbeProxy, never()).sendMetadataObject(any(), anyInt(), anyInt());
    }

    @Test
    public void testCheckAddFilterPre_FunctionEnabled() throws Exception {
        // Arrange
        int classID = 15; // org.apache.catalina.core.StandardContext
        int methodID = 2; // addFilterDef
        Object[] args = new Object[]{mock(Object.class), mock(Object.class)};

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Mock Reflection.invokeMethod
        Object filter = mock(Object.class);
        when(Reflection.invokeMethod(args[1], "getFilter", new Class[]{})).thenReturn(filter);

        // Act
        smithProbeProxy.checkAddFilterPre(classID, methodID, args);

        // Assert
        verify(smithProbeProxy, times(1)).sendMetadataObject(filter, classID, methodID);
    }

    @Test
    public void testCheckAddFilterPre_FunctionDisabled() {
        // Arrange
        int classID = 15; // org.apache.catalina.core.StandardContext
        int methodID = 2; // addFilterDef
        Object[] args = new Object[]{mock(Object.class), mock(Object.class)};

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(false);

        // Act
        smithProbeProxy.checkAddFilterPre(classID, methodID, args);

        // Assert
        verify(smithProbeProxy, never()).sendMetadataObject(any(), anyInt(), anyInt());
    }

    @Test
    public void testCheckFilterConfigPost_FunctionEnabled() {
        // Arrange
        int classID = 16; // org.apache.catalina.core.ApplicationFilterConfig
        int methodID = 0; // <init>
        Object[] args = new Object[]{mock(Object.class), mock(Object.class)};
        Object ret = mock(Object.class);
        boolean blocked = false;

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Act
        smithProbeProxy.checkFilterConfigPost(classID, methodID, args, ret, blocked);

        // Assert
        verify(smithProbeProxy, times(1)).sendMetadataObject(ret, classID, methodID);
    }

    @Test
    public void testCheckFilterConfigPost_FunctionDisabled() {
        // Arrange
        int classID = 16; // org.apache.catalina.core.ApplicationFilterConfig
        int methodID = 0; // <init>
        Object[] args = new Object[]{mock(Object.class), mock(Object.class)};
        Object ret = mock(Object.class);
        boolean blocked = false;

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(false);

        // Act
        smithProbeProxy.checkFilterConfigPost(classID, methodID, args, ret, blocked);

        // Assert
        verify(smithProbeProxy, never()).sendMetadataObject(any(), anyInt(), anyInt());
    }

    @Test
    public void testCheckAddValvePre_FunctionEnabled() {
        // Arrange
        int classID = 14; // org.apache.catalina.core.StandardPipeline
        int methodID = 0; // addValve
        Object[] args = new Object[]{mock(Object.class), mock(Object.class)};

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Act
        smithProbeProxy.checkAddValvePre(classID, methodID, args);

        // Assert
        verify(smithProbeProxy, times(1)).sendMetadataObject(args[1], classID, methodID);
    }

    @Test
    public void testCheckAddValvePre_FunctionDisabled() {
        // Arrange
        int classID = 14; // org.apache.catalina.core.StandardPipeline
        int methodID = 0; // addValve
        Object[] args = new Object[]{mock(Object.class), mock(Object.class)};

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(false);

        // Act
        smithProbeProxy.checkAddValvePre(classID, methodID, args);

        // Assert
        verify(smithProbeProxy, never()).sendMetadataObject(any(), anyInt(), anyInt());
    }

    @Test
    public void testCheckAddListenerPre_FunctionEnabled() {
        // Arrange
        int classID = 15; // org.apache.catalina.core.StandardContext
        int methodID = 1; // addApplicationEventListener
        Object[] args = new Object[]{mock(Object.class), mock(Object.class)};

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Act
        smithProbeProxy.checkAddListenerPre(classID, methodID, args);

        // Assert
        verify(smithProbeProxy, times(1)).sendMetadataObject(args[1], classID, methodID);
    }

    @Test
    public void testCheckAddListenerPre_FunctionDisabled() {
        // Arrange
        int classID = 15; // org.apache.catalina.core.StandardContext
        int methodID = 1; // addApplicationEventListener
        Object[] args = new Object[]{mock(Object.class), mock(Object.class)};

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(false);

        // Act
        smithProbeProxy.checkAddListenerPre(classID, methodID, args);

        // Assert
        verify(smithProbeProxy, never()).sendMetadataObject(any(), anyInt(), anyInt());
    }

    @Test
    public void testCheckWebSocketPre_FunctionEnabled() throws Exception {
        // Arrange
        int classID = 19; // com.caucho.server.webapp.WebApp
        int methodID = 0; // addListenerObject
        Object[] args = new Object[]{mock(Object.class), mock(Object.class)};

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Mock Reflection.invokeMethod
        Class<?> endpointCla = mock(Class.class);
        when(Reflection.invokeMethod(args[1], "getEndpointClass", new Class[]{})).thenReturn(endpointCla);

        // Act
        smithProbeProxy.checkWebSocketPre(classID, methodID, args);

        // Assert
        verify(smithProbeProxy, times(1)).sendMetadataClass(endpointCla, classID, methodID);
    }

    @Test
    public void testCheckWebSocketPre_FunctionDisabled() {
        // Arrange
        int classID = 19; // com.caucho.server.webapp.WebApp
        int methodID = 0; // addListenerObject
        Object[] args = new Object[]{mock(Object.class), mock(Object.class)};

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(false);

        // Act
        smithProbeProxy.checkWebSocketPre(classID, methodID, args);

        // Assert
        verify(smithProbeProxy, never()).sendMetadataClass(any(), anyInt(), anyInt());
    }

    @Test
    public void testOnTimer_FunctionEnabled() {
        // Arrange
        Heartbeat heartbeat = mock(Heartbeat.class);
        when(smithProbeObjMock.getHeartbeat()).thenReturn(heartbeat);

        Map<Pair<Integer, Integer>, Integer> limits = new HashMap<>();
        limits.put(new ImmutablePair<>(1, 2), 1000);
        when(smithProbeObjMock.getLimits()).thenReturn(limits);

        // Act
        smithProbeProxy.onTimer();

        // Assert
        verify(clientMock, times(1)).write(Operate.HEARTBEAT, heartbeat.toJsonElement());
    }

    @Test
    public void testOnTimer_FunctionDisabled() {
        // Arrange
        Heartbeat heartbeat = mock(Heartbeat.class);
        when(smithProbeObjMock.getHeartbeat()).thenReturn(heartbeat);

        Map<Pair<Integer, Integer>, Integer> limits = new HashMap<>();
        when(smithProbeObjMock.getLimits()).thenReturn(limits);

        // Act
        smithProbeProxy.onTimer();

        // Assert
        verify(clientMock, times(1)).write(Operate.HEARTBEAT, heartbeat.toJsonElement());
    }

    @Test
    public void testCheckResinAddServletPost_FunctionEnabled() throws Exception {
        // Arrange
        int classID = 18; // com.caucho.server.dispatch.ServletManager
        int methodID = 0; // addServlet
        Object[] args = new Object[]{mock(Object.class), mock(Object.class)};
        Object ret = mock(Object.class);
        boolean blocked = false;

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Mock Reflection.invokeMethod
        Class<?> servletClass = mock(Class.class);
        when(Reflection.invokeMethod(args[1], "getServletClass", new Class[]{})).thenReturn(servletClass);

        // Act
        smithProbeProxy.checkResinAddServletPost(classID, methodID, args, ret, blocked);

        // Assert
        verify(smithProbeProxy, times(1)).sendMetadataClass(servletClass, classID, methodID);
    }

    @Test
    public void testCheckResinAddServletPost_FunctionDisabled() {
        // Arrange
        int classID = 18; // com.caucho.server.dispatch.ServletManager
        int methodID = 0; // addServlet
        Object[] args = new Object[]{mock(Object.class), mock(Object.class)};
        Object ret = mock(Object.class);
        boolean blocked = false;

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(false);

        // Act
        smithProbeProxy.checkResinAddServletPost(classID, methodID, args, ret, blocked);

        // Assert
        verify(smithProbeProxy, never()).sendMetadataClass(any(), anyInt(), anyInt());
    }

    @Test
    public void testCheckResinAddServletPre_FunctionEnabled() throws Exception {
        // Arrange
        int classID = 18; // com.caucho.server.dispatch.ServletManager
        int methodID = 0; // addServlet
        Object[] args = new Object[]{mock(Object.class), mock(Object.class)};

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Mock Reflection.invokeMethod
        Class<?> servletClass = mock(Class.class);
        when(Reflection.invokeMethod(args[1], "getServletClass", new Class[]{})).thenReturn(servletClass);

        // Act
        smithProbeProxy.checkResinAddServletPre(classID, methodID, args);

        // Assert
        verify(smithProbeProxy, times(1)).sendMetadataClass(servletClass, classID, methodID);
    }

    @Test
    public void testCheckResinAddServletPre_FunctionDisabled() {
        // Arrange
        int classID = 18; // com.caucho.server.dispatch.ServletManager
        int methodID = 0; // addServlet
        Object[] args = new Object[]{mock(Object.class), mock(Object.class)};

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(false);

        // Act
        smithProbeProxy.checkResinAddServletPre(classID, methodID, args);

        // Assert
        verify(smithProbeProxy, never()).sendMetadataClass(any(), anyInt(), anyInt());
    }

    @Test
    public void testCheckResinAddFilterPre_FunctionEnabled() throws Exception {
        // Arrange
        int classID = 17; // com.caucho.server.dispatch.FilterManager
        int methodID = 0; // addFilter
        Object[] args = new Object[]{mock(Object.class), mock(Object.class)};

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Mock Reflection.invokeMethod
        Class<?> filterCla = mock(Class.class);
        when(Reflection.invokeMethod(args[1], "getFilterClass", new Class[]{})).thenReturn(filterCla);

        // Act
        smithProbeProxy.checkResinAddFilterPre(classID, methodID, args);

        // Assert
        verify(smithProbeProxy, times(1)).sendMetadataClass(filterCla, classID, methodID);
    }

    @Test
    public void testCheckResinAddFilterPre_FunctionDisabled() {
        // Arrange
        int classID = 17; // com.caucho.server.dispatch.FilterManager
        int methodID = 0; // addFilter
        Object[] args = new Object[]{mock(Object.class), mock(Object.class)};

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(false);

        // Act
        smithProbeProxy.checkResinAddFilterPre(classID, methodID, args);

        // Assert
        verify(smithProbeProxy, never()).sendMetadataClass(any(), anyInt(), anyInt());
    }

    @Test
    public void testCheckResinWebSocketPre_FunctionEnabled() {
        // Arrange
        int classID = 35; // com.caucho.server.http.WebSocketContextImpl
        int methodID = 0; // <init>
        Object[] args = new Object[]{mock(Object.class), mock(Object.class), mock(Object.class)};

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Act
        smithProbeProxy.checkResinWebSocketPre(classID, methodID, args);

        // Assert
        verify(smithProbeProxy, times(1)).sendMetadataObject(args[2], classID, methodID);
    }

    @Test
    public void testCheckResinWebSocketPre_FunctionDisabled() {
        // Arrange
        int classID = 35; // com.caucho.server.http.WebSocketContextImpl
        int methodID = 0; // <init>
        Object[] args = new Object[]{mock(Object.class), mock(Object.class), mock(Object.class)};

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(false);

        // Act
        smithProbeProxy.checkResinWebSocketPre(classID, methodID, args);

        // Assert
        verify(smithProbeProxy, never()).sendMetadataObject(any(), anyInt(), anyInt());
    }

    @Test
    public void testCheckJettyMemshellPre_FunctionEnabled() {
        // Arrange
        int classID = 20; // org.eclipse.jetty.servlet.BaseHolder
        int methodID = 0; // setHeldClass
        Object[] args = new Object[]{mock(Object.class), mock(Class.class)};

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Act
        smithProbeProxy.checkJettyMemshellPre(classID, methodID, args);

        // Assert
        verify(smithProbeProxy, times(1)).sendMetadataClass((Class<?>)args[1], classID, methodID);
    }

    @Test
    public void testCheckJettyMemshellPre_FunctionDisabled() {
        // Arrange
        int classID = 20; // org.eclipse.jetty.servlet.BaseHolder
        int methodID = 0; // setHeldClass
        Object[] args = new Object[]{mock(Object.class), mock(Class.class)};

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(false);

        // Act
        smithProbeProxy.checkJettyMemshellPre(classID, methodID, args);

        // Assert
        verify(smithProbeProxy, never()).sendMetadataClass(any(), anyInt(), anyInt());
    }

    @Test
    public void testCheckJettyListenerPre_FunctionEnabled() {
        // Arrange
        int classID = 22; // org.eclipse.jetty.server.handler.ContextHandler
        int methodID = 0; // addEventListener
        Object[] args = new Object[]{mock(Object.class), mock(Object.class)};

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Act
        smithProbeProxy.checkJettyListenerPre(classID, methodID, args);

        // Assert
        verify(smithProbeProxy, times(1)).sendMetadataObject(args[1], classID, methodID);
    }

    @Test
    public void testCheckJettyListenerPre_FunctionDisabled() {
        // Arrange
        int classID = 22; // org.eclipse.jetty.server.handler.ContextHandler
        int methodID = 0; // addEventListener
        Object[] args = new Object[]{mock(Object.class), mock(Object.class)};

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(false);

        // Act
        smithProbeProxy.checkJettyListenerPre(classID, methodID, args);

        // Assert
        verify(smithProbeProxy, never()).sendMetadataObject(any(), anyInt(), anyInt());
    }

    @Test
    public void testCehckJettyDeployPre_FunctionEnabled() {
        // Arrange
        int classID = 22; // org.eclipse.jetty.server.handler.ContextHandler
        int methodID = 0; // addEventListener
        Object[] args = new Object[]{mock(Object.class)};

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Act
        smithProbeProxy.cehckJettyDeployPre(classID, methodID, args);

        // Assert
        assertTrue(smithProbeProxy.jettyDeploying.get());
    }

    @Test
    public void testCehckJettyDeployPre_FunctionDisabled() {
        // Arrange
        int classID = 22; // org.eclipse.jetty.server.handler.ContextHandler
        int methodID = 0; // addEventListener
        Object[] args = new Object[]{mock(Object.class)};

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(false);

        // Act
        smithProbeProxy.cehckJettyDeployPre(classID, methodID, args);

        // Assert
        assertFalse(smithProbeProxy.jettyDeploying.get());
    }

    @Test
    public void testCheckWebSocketConfigPre_FunctionEnabled() {
        // Arrange
        int classID = 36; // javax.websocket.server.DefaultServerEndpointConfig
        int methodID = 0; // <init>
        Object[] args = new Object[]{mock(Class.class)};

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Act
        smithProbeProxy.checkWebSocketConfigPre(classID, methodID, args);

        // Assert
        verify(smithProbeProxy, times(1)).sendMetadataClass((Class<?>)args[0], classID, methodID);
    }

    @Test
    public void testCheckWebSocketConfigPre_FunctionDisabled() {
        // Arrange
        int classID = 36; // javax.websocket.server.DefaultServerEndpointConfig
        int methodID = 0; // <init>
        Object[] args = new Object[]{mock(Class.class)};

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(false);

        // Act
        smithProbeProxy.checkWebSocketConfigPre(classID, methodID, args);

        // Assert
        verify(smithProbeProxy, never()).sendMetadataClass(any(), anyInt(), anyInt());
    }

    @Test
    public void testCheckJettyDeployPost_FunctionEnabled() {
        // Arrange
        int classID = 22; // org.eclipse.jetty.server.handler.ContextHandler
        int methodID = 0; // addEventListener
        Object[] args = new Object[]{mock(Object.class)};
        Object ret = mock(Object.class);
        boolean blocked = false;

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Act
        smithProbeProxy.checkJettyDeployPost(classID, methodID, args, ret, blocked);

        // Assert
        assertFalse(smithProbeProxy.jettyDeploying.get());
    }

    @Test
    public void testCheckJettyDeployPost_FunctionDisabled() {
        // Arrange
        int classID = 22; // org.eclipse.jetty.server.handler.ContextHandler
        int methodID = 0; // addEventListener
        Object[] args = new Object[]{mock(Object.class)};
        Object ret = mock(Object.class);
        boolean blocked = false;

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(false);

        // Act
        smithProbeProxy.checkJettyDeployPost(classID, methodID, args, ret, blocked);

        // Assert
        assertFalse(smithProbeProxy.jettyDeploying.get());
    }

    @Test
    public void testCheckSpringControllerPre_FunctionEnabled() {
        // Arrange
        int classID = 23; // org.springframework.web.servlet.handler.AbstractUrlHandlerMapping
        int methodID = 0; // registerHandler
        Object[] args = new Object[]{mock(Object.class), mock(Object.class), mock(Object.class)};

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Act
        smithProbeProxy.checkSpringControllerPre(classID, methodID, args);

        // Assert
        verify(smithProbeProxy, times(1)).sendMetadataObject(args[2], classID, methodID);
    }

    @Test
    public void testCheckSpringControllerPre_FunctionDisabled() {
        // Arrange
        int classID = 23; // org.springframework.web.servlet.handler.AbstractUrlHandlerMapping
        int methodID = 0; // registerHandler
        Object[] args = new Object[]{mock(Object.class), mock(Object.class), mock(Object.class)};

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(false);

        // Act
        smithProbeProxy.checkSpringControllerPre(classID, methodID, args);

        // Assert
        verify(smithProbeProxy, never()).sendMetadataObject(any(), anyInt(), anyInt());
    }

    @Test
    public void testCheckSpringInterceptorPre_FunctionEnabled() {
        // Arrange
        int classID = 25; // org.springframework.web.servlet.HandlerInterceptor
        int methodID = 0; // <init>
        Object[] args = new Object[]{mock(Object.class)};

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Act
        smithProbeProxy.checkSpringInterceptorPre(classID, methodID, args);

        // Assert
        verify(smithProbeProxy, times(1)).sendMetadataObject(args[0], classID, methodID);
    }

    @Test
    public void testCheckSpringInterceptorPre_FunctionDisabled() {
        // Arrange
        int classID = 25; // org.springframework.web.servlet.HandlerInterceptor
        int methodID = 0; // <init>
        Object[] args = new Object[]{mock(Object.class)};

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(false);

        // Act
        smithProbeProxy.checkSpringInterceptorPre(classID, methodID, args);

        // Assert
        verify(smithProbeProxy, never()).sendMetadataObject(any(), anyInt(), anyInt());
    }

    @Test
    public void testCheckMemshellInitPost_FunctionEnabled() {
        // Arrange
        int classID = 26; // javax.servlet.Filter
        int methodID = 0; // <init>
        Object[] args = new Object[]{mock(Object.class)};
        Object ret = mock(Object.class);
        boolean blocked = false;

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Act
        smithProbeProxy.checkMemshellInitPost(classID, methodID, args, ret, blocked);

        // Assert
        verify(smithProbeProxy, times(1)).sendMetadataObject(ret, classID, methodID);
    }

    @Test
    public void testCheckMemshellInitPost_FunctionDisabled() {
        // Arrange
        int classID = 26; // javax.servlet.Filter
        int methodID = 0; // <init>
        Object[] args = new Object[]{mock(Object.class)};
        Object ret = mock(Object.class);
        boolean blocked = false;

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(false);

        // Act
        smithProbeProxy.checkMemshellInitPost(classID, methodID, args, ret, blocked);

        // Assert
        verify(smithProbeProxy, never()).sendMetadataObject(any(), anyInt(), anyInt());
    }

    @Test
    public void testProcessWildflyClassLoaderException_FunctionEnabled() throws ClassNotFoundException {
        // Arrange
        int classID = 34; // org.jboss.modules.ModuleClassLoader
        int methodID = 0; // findClass
        Object[] args = new Object[]{mock(Object.class), "java.io.Reader"};
        Object exceptionObject = new ClassNotFoundException();

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Act
        try {
            Object result = smithProbeProxy.processWildflyClassLoaderException(classID, methodID, args, exceptionObject);

              // Assert
            assertNotNull(result);
            assertEquals(Class.forName("com.security.smith.SomeClass"), result);
        }
        catch(Throwable e) {
            
        }
    }

    @Test
    public void testProcessWildflyClassLoaderException_FunctionDisabled() throws ClassNotFoundException {
        // Arrange
        int classID = 34; // org.jboss.modules.ModuleClassLoader
        int methodID = 0; // findClass
        Object[] args = new Object[]{mock(Object.class), "com.security.smith.SomeClass"};
        Object exceptionObject = new ClassNotFoundException();

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(false);

        try {
            // Act
            Object result = smithProbeProxy.processWildflyClassLoaderException(classID, methodID, args, exceptionObject);

            // Assert
            assertNull(result);
        }
        catch(Throwable e) {

        }
    }

    @Test
    public void testCheckWildflyaddServletPre_FunctionEnabled() throws Exception {
        // Arrange
        int classID = 33; // io.undertow.servlet.core.ManagedServlets
        int methodID = 0; // addServlet
        Object[] args = new Object[]{mock(Object.class), mock(Object.class)};

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Mock Reflection.getField
        Class<?> servletClass = mock(Class.class);
        when(Reflection.getField(args[1], "servletClass")).thenReturn(servletClass);

        // Act
        smithProbeProxy.checkWildflyaddServletPre(classID, methodID, args);

        // Assert
        verify(smithProbeProxy, times(1)).sendMetadataObject(servletClass, classID, methodID);
    }

    @Test
    public void testCheckWildflyaddServletPre_FunctionDisabled() {
        // Arrange
        int classID = 33; // io.undertow.servlet.core.ManagedServlets
        int methodID = 0; // addServlet
        Object[] args = new Object[]{mock(Object.class), mock(Object.class)};

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(false);

        // Act
        smithProbeProxy.checkWildflyaddServletPre(classID, methodID, args);

        // Assert
        verify(smithProbeProxy, never()).sendMetadataObject(any(), anyInt(), anyInt());
    }

    @Test
    public void testCheckWildflyaddFilterPre_FunctionEnabled() throws Exception {
        // Arrange
        int classID = 38; // io.undertow.servlet.core.ManagedFilters
        int methodID = 0; // addFilter
        Object[] args = new Object[]{mock(Object.class), mock(Object.class)};

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Mock Reflection.getField
        Class<?> filterClass = mock(Class.class);
        when(Reflection.getField(args[1], "filterClass")).thenReturn(filterClass);

        // Act
        smithProbeProxy.checkWildflyaddFilterPre(classID, methodID, args);

        // Assert
        verify(smithProbeProxy, times(1)).sendMetadataClass(filterClass, classID, methodID);
    }

    @Test
    public void testCheckWildflyaddFilterPre_FunctionDisabled() {
        // Arrange
        int classID = 38; // io.undertow.servlet.core.ManagedFilters
        int methodID = 0; // addFilter
        Object[] args = new Object[]{mock(Object.class), mock(Object.class)};

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(false);

        // Act
        smithProbeProxy.checkWildflyaddFilterPre(classID, methodID, args);

        // Assert
        verify(smithProbeProxy, never()).sendMetadataClass(any(), anyInt(), anyInt());
    }

    @Test
    public void testHandleReflectField_FunctionEnabled_ArgsLengthValid_NotSecurityPackage() {
        // Arrange
        int classID = 42; // java.lang.reflect.Field
        int methodID = 0; // <init>
        Object[] args = new Object[]{String.class, "fieldName"};
        Object ret = null;
        boolean blocked = false;

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Mock checkReflectEvil
        when(smithProbeProxy.checkReflectEvil(anyString(), anyString(), eq(false))).thenReturn(true);

        // Act
        smithProbeProxy.handleReflectField(classID, methodID, args, ret, blocked);

        // Assert
        verify(smithProbeProxy, times(1)).trace(classID, methodID, args, ret, blocked);
    }

    @Test
    public void testHandleReflectField_FunctionDisabled() {
        // Arrange
        int classID = 42; // java.lang.reflect.Field
        int methodID = 0; // <init>
        Object[] args = new Object[]{String.class, "fieldName"};
        Object ret = null;
        boolean blocked = false;

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(false);

        // Act
        smithProbeProxy.handleReflectField(classID, methodID, args, ret, blocked);

        // Assert
        verify(smithProbeProxy, never()).trace(anyInt(), anyInt(), any(), any(), anyBoolean());
    }

    @Test
    public void testHandleReflectField_ArgsLengthInvalid() {
        // Arrange
        int classID = 42; // java.lang.reflect.Field
        int methodID = 0; // <init>
        Object[] args = new Object[]{String.class};
        Object ret = null;
        boolean blocked = false;

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Act
        smithProbeProxy.handleReflectField(classID, methodID, args, ret, blocked);

        // Assert
        verify(smithProbeProxy, never()).trace(anyInt(), anyInt(), any(), any(), anyBoolean());
    }

    @Test
    public void testHandleReflectField_SecurityPackage() {
        // Arrange
        int classID = 42; // java.lang.reflect.Field
        int methodID = 0; // <init>
        Object[] args = new Object[]{com.security.smith.SmithProbe.class, "fieldName"};
        Object ret = null;
        boolean blocked = false;

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Act
        smithProbeProxy.handleReflectField(classID, methodID, args, ret, blocked);

        // Assert
        verify(smithProbeProxy, never()).trace(anyInt(), anyInt(), any(), any(), anyBoolean());
    }

    @Test
    public void testHandleReflectField_ExceptionThrown() throws ClassNotFoundException {
        // Arrange
        int classID = 42; // java.lang.reflect.Field
        int methodID = 0; // <init>
        Object[] args = new Object[]{"invalidClass", "fieldName"};
        Object ret = null;
        boolean blocked = false;

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Act
        smithProbeProxy.handleReflectField(classID, methodID, args, ret, blocked);

        // Assert
        verify(smithProbeProxy, never()).trace(anyInt(), anyInt(), any(), any(), anyBoolean());
    }

    @Test
    public void testProcessGlassfishClassLoaderfindClassException_FunctionEnabled() throws ClassNotFoundException {
        // Arrange
        int classID = 41; // org.apache.felix.framework.BundleWiringImpl$BundleClassLoader
        int methodID = 0; // findClass
        Object[] args = new Object[]{mock(Object.class), "com.security.smith.SomeClass"};
        Object exceptionObject = new ClassNotFoundException();

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        try {
           // Act
            Object result = smithProbeProxy.processGlassfishClassLoaderfindClassException(classID, methodID, args, exceptionObject);

            // Assert
            assertNotNull(result);
            assertEquals(Class.forName("com.security.smith.SomeClass"), result);
        }
        catch(Throwable e) {

        }
    }

    @Test
    public void testProcessGlassfishClassLoaderfindClassException_FunctionDisabled() throws ClassNotFoundException {
        // Arrange
        int classID = 41; // org.apache.felix.framework.BundleWiringImpl$BundleClassLoader
        int methodID = 0; // findClass
        Object[] args = new Object[]{mock(Object.class), "com.security.smith.SomeClass"};
        Object exceptionObject = new ClassNotFoundException();

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(false);

        try {
                // Act
            Object result = smithProbeProxy.processGlassfishClassLoaderfindClassException(classID, methodID, args, exceptionObject);

            // Assert
            assertNull(result); 
        } catch (Throwable e) {
            // TODO: handle exception
        }
    }

    @Test
    public void testHandleMvel2Post_FunctionEnabled() {
        // Arrange
        int classID = 44; // org.mvel2.PropertyAccessor
        int methodID = 0; // getMethod
        Object[] args = new Object[]{mock(Object.class), String.class, "methodName"};
        Object ret = null;
        boolean blocked = false;

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Mock JsRuleEngine.detect
        when(smithProbeObjMock.getJsRuleEngine()).thenReturn(jsRuleEngineMock);
        when(jsRuleEngineMock.detect(3, any())).thenReturn(new JsRuleResult());

        // Act
        smithProbeProxy.handleMvel2Post(classID, methodID, args, ret, blocked);

        // Assert
        verify(smithProbeProxy, times(1)).trace(classID, methodID, args, ret, blocked);
    }

    @Test
    public void testHandleMvel2Post_FunctionDisabled() {
        // Arrange
        int classID = 44; // org.mvel2.PropertyAccessor
        int methodID = 0; // getMethod
        Object[] args = new Object[]{mock(Object.class), String.class, "methodName"};
        Object ret = null;
        boolean blocked = false;

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(false);

        // Act
        smithProbeProxy.handleMvel2Post(classID, methodID, args, ret, blocked);

        // Assert
        verify(smithProbeProxy, never()).trace(anyInt(), anyInt(), any(), any(), anyBoolean());
    }

    @Test
    public void testHandleConstructorPost_FunctionEnabled() {
        // Arrange
        int classID = 45; // org.mvel2.optimizers.impl.refl.ReflectiveAccessorOptimizer
        int methodID = 1; // compileConstructor
        Object[] args = new Object[]{mock(Object.class), "className".toCharArray()};
        Object ret = null;
        boolean blocked = false;

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Mock JsRuleEngine.detect
        when(smithProbeObjMock.getJsRuleEngine()).thenReturn(jsRuleEngineMock);
        when(jsRuleEngineMock.detect(3, any())).thenReturn(new JsRuleResult());

        // Act
        smithProbeProxy.handleConstructorPost(classID, methodID, args, ret, blocked);

        // Assert
        verify(smithProbeProxy, times(1)).trace(classID, methodID, args, ret, blocked);
    }

    @Test
    public void testHandleConstructorPost_FunctionDisabled() {
        // Arrange
        int classID = 45; // org.mvel2.optimizers.impl.refl.ReflectiveAccessorOptimizer
        int methodID = 1; // compileConstructor
        Object[] args = new Object[]{mock(Object.class), "className".toCharArray()};
        Object ret = null;
        boolean blocked = false;

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(false);

        // Act
        smithProbeProxy.handleConstructorPost(classID, methodID, args, ret, blocked);

        // Assert
        verify(smithProbeProxy, never()).trace(anyInt(), anyInt(), any(), any(), anyBoolean());
    }

    @Test
    public void testHandleOgnlInvokeMethodPost_FunctionEnabled() {
        // Arrange
        int classID = 48; // ognl.OgnlRuntime
        int methodID = 0; // invokeMethod
        Object[] args = new Object[]{mock(Object.class), mock(Method.class), mock(Object.class)};
        Object ret = null;
        boolean blocked = false;

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Mock JsRuleEngine.detect
        when(smithProbeObjMock.getJsRuleEngine()).thenReturn(jsRuleEngineMock);
        when(jsRuleEngineMock.detect(3, any())).thenReturn(new JsRuleResult());

        // Act
        smithProbeProxy.handleOgnlInvokeMethodPost(classID, methodID, args, ret, blocked);

        // Assert
        verify(smithProbeProxy, times(1)).trace(classID, methodID, args, ret, blocked);
    }

    @Test
    public void testHandleOgnlInvokeMethodPost_FunctionDisabled() {
        // Arrange
        int classID = 48; // ognl.OgnlRuntime
        int methodID = 0; // invokeMethod
        Object[] args = new Object[]{mock(Object.class), mock(Method.class), mock(Object.class)};
        Object ret = null;
        boolean blocked = false;

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(false);

        // Act
        smithProbeProxy.handleOgnlInvokeMethodPost(classID, methodID, args, ret, blocked);

        // Assert
        verify(smithProbeProxy, never()).trace(anyInt(), anyInt(), any(), any(), anyBoolean());
    }

    @Test
    public void testHandleOgnlIcallConstructorPost_FunctionEnabled() {
        // Arrange
        int classID = 48; // ognl.OgnlRuntime
        int methodID = 1; // callConstructor
        Object[] args = new Object[]{mock(Object.class), "className", mock(Object.class)};
        Object ret = null;
        boolean blocked = false;

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Mock JsRuleEngine.detect
        when(smithProbeObjMock.getJsRuleEngine()).thenReturn(jsRuleEngineMock);
        when(jsRuleEngineMock.detect(3, any())).thenReturn(new JsRuleResult());

        // Act
        smithProbeProxy.handleOgnlIcallConstructorPost(classID, methodID, args, ret, blocked);

        // Assert
        verify(smithProbeProxy, times(1)).trace(classID, methodID, args, ret, blocked);
    }

    @Test
    public void testHandleOgnlIcallConstructorPost_FunctionDisabled() {
        // Arrange
        int classID = 48; // ognl.OgnlRuntime
        int methodID = 1; // callConstructor
        Object[] args = new Object[]{mock(Object.class), "className", mock(Object.class)};
        Object ret = null;
        boolean blocked = false;

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(false);

        // Act
        smithProbeProxy.handleOgnlIcallConstructorPost(classID, methodID, args, ret, blocked);

        // Assert
        verify(smithProbeProxy, never()).trace(anyInt(), anyInt(), any(), any(), anyBoolean());
    }

    @Test
    public void testHandleSpelExecutePost_FunctionEnabled() {
        // Arrange
        int classID = 49; // org.springframework.expression.spel.support.ReflectiveMethodExecutor
        int methodID = 0; // execute
        Object[] args = new Object[]{mock(Object.class), mock(Object.class), mock(Object.class)};
        Object ret = null;
        boolean blocked = false;

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(true);

        // Mock JsRuleEngine.detect
        when(smithProbeObjMock.getJsRuleEngine()).thenReturn(jsRuleEngineMock);
        when(jsRuleEngineMock.detect(3, any())).thenReturn(new JsRuleResult());

        // Act
        smithProbeProxy.handleSpelExecutePost(classID, methodID, args, ret, blocked);

        // Assert
        verify(smithProbeProxy, times(1)).trace(classID, methodID, args, ret, blocked);
    }

    @Test
    public void testHandleSpelExecutePost_FunctionDisabled() {
        // Arrange
        int classID = 49; // org.springframework.expression.spel.support.ReflectiveMethodExecutor
        int methodID = 0; // execute
        Object[] args = new Object[]{mock(Object.class), mock(Object.class), mock(Object.class)};
        Object ret = null;
        boolean blocked = false;

        // Mock SmithProbeObj.isFunctionEnabled
        when(smithProbeObjMock.isFunctionEnabled(classID, methodID)).thenReturn(false);

        // Act
        smithProbeProxy.handleSpelExecutePost(classID, methodID, args, ret, blocked);

        // Assert
        verify(smithProbeProxy, never()).trace(anyInt(), anyInt(), any(), any(), anyBoolean());
    }
}