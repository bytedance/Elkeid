# JVM Probe
## 编译
```shell script
./build.sh
./gradlew example:build
```
## 测试
```shell script
# run example
java -jar $(pwd)/example/build/libs/example-1.0-SNAPSHOT.jar

# run server
python $(pwd)/script/server.py

# inject probe
bash $(pwd)/script/jattach.sh -c load --args "instrument false $(pwd)/output/SmithAgent.jar" -p {pid}
```
## 原理
JVM提供动态attach机制, 支持动态注入jar包.
```java
package com.security.smith;

import com.sun.tools.attach.AgentInitializationException;
import com.sun.tools.attach.AgentLoadException;
import com.sun.tools.attach.AttachNotSupportedException;
import com.sun.tools.attach.VirtualMachine;

import java.io.IOException;

public class AgentLoader {
    public static void main(String[] args) {
        if (args.length != 2) {
            System.out.println("usage: program <pid> <jar>");
            return;
        }

        String pid = args[0];
        String jarPath = args[1];

        System.out.println("pid: " + pid + " jar: " + jarPath);

        try {
            VirtualMachine vm = VirtualMachine.attach(pid);

            vm.loadAgent(jarPath);
            vm.detach();
        } catch (AttachNotSupportedException | IOException | AgentLoadException | AgentInitializationException e) {
            e.printStackTrace();
        }
    }
}
```
使用方法如上, attach的过程分为3步:
- 检查临时目录下是否有.java_pid{pid} unix socket文件
- 没有则创建.attach_pid{pid}文件, 给目标进程发送信号3
- 目标进程JVM虚拟机收到信号, 创建.java_pid{pid} unix socket文件

基于unix socket, 可以给JVM发送指令, 例如"load"指令可以加载.so文件, VirtualMachine.loadAgent也是基于load指令实现的. loadAgent内部发送"load"指令, 使JVM加载自带的".so", 动态库内部加载参数指定的jar包.
jar包的MANIFEST.MF需要提供必要参数:
```=
Manifest-Version: 1.0
Agent-Class: com.security.smith.SmithAgent
Can-Retransform-Classes: true
Boot-Class-Path: SmithAgent.jar
```
Agent-Class指定入口Class, 该Class需要实现入口方法:
```java
public class SmithAgent {
    public static void agentmain(String agentArgs, Instrumentation inst) {

    }
}
```
## Hook
Instrumentation类提供一系列功能:
1. ClassFileTransformer用于拦截类加载事件, 需要注册到Instrumentation
2. Instrumentation.redefineClasses
   - 针对已加载的类, 舍弃原本的字节码, 替换为由用户提供的byte数组
   - 功能比较危险, 一般用于修复出错的字节码
3. Instrumentation.retransformClasses
    - 针对已加载的类, 重新调用所有已注册的ClassFileTransformer的transform方法, 两个场景
    - 在执行premain和agentmain方法前, JVM已经加载了不少类
        - 而这些类的加载事件并没有被拦截并执行相关的注入逻辑
    - 定义了多个Java Agent, 多个注入的情况, 可能需要移除其中的部分注入
        - 调用Instrumentation.removeTransformer去除某个注入类后, 可以调用retransformClasses
        - 重新从原始byte数组开始进行注入
4. Java Agent的功能是通过JVMTI Agent（C Agent）, JVMTI是一个事件驱动的工具实现接口
    - 通常会在C Agent加载后的方法入口Agent_OnLoad处注册各种事件的钩子方法
    - 当JVM触发这些事件时, 便会调用对应的钩子方法
    - 例如可以为JVMTI中的ClassFileLoadHook事件设置钩子, 从而在C层面拦截所有的类加载事件

使用Instrumentation可以添加Class拦截器, 在Class加载时能够插入或修改字节码, 达到控制整个Class的目的. 对于已经加载的Class, 可以使用retransformClasses强行重载Class, 拦截器便能对重载的Class进行拦截.
```java
public class SmithProbe implements ClassFileTransformer {
    public void start() {
        inst.addTransformer(this, true);

        try {
            inst.retransformClasses(Runtime.class);

        } catch (UnmodifiableClassException e) {
            e.printStackTrace();
        }
    }

    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer) {
        return null;
    }
}
```
classfileBuffer就是目标Class的字节码流, 使用asm等库可以解析字节码并篡改, 返回篡改后的字节码流即可篡改Class, 返回null则示意JVM加载原本的字节码.
## JVM函数调用
JVM函数调用基于栈, 例如调用Runtime.exec, 需要依次将类实例引用, exec的函数参数推出栈, 伪代码如下:
```=
# 假定类实例存在寄存器1中, 将寄存器1的值推入栈
ALOAD 1
# 将字符串"ls"推入栈
LDC "ls"
# 调用函数, 因为Java支持重载, 需要指定参数签名
INVOKEVIRTUAL Runtime.exec (Ljava/lang/String;)Ljava/lang/Process;
```
而进入函数之后, JVM自动根据参数个数, 帮方法将参数放入寄存器(0+), 所以方法内获取参数:
```=
# 获取类实例, 静态方法无实例, 所以0寄存器保存的是第一个参数
ALOAD 0
# 获取字符串参数"ls"
ALOAD 1
```
## 设计
根据上面分析, 要将函数调用的参数信息传出, 只需要在每个函数的开头插入一段字节码, 但是字节码需要动态生成. 没有一段字节码能够搞定所有函数, 因为每个函数的参数个数以及类型都不同. 所以Hook还是需要我们设定好函数的参数类型以及签名.
例如针对Runtime.exe(String), 我们设定函数信息:
```=
java/lang/Runtime VIRTUAL_METHOD_TYPE exec {"string"}
```
那么在对Class进行拦截时, 我们可以根据上面的设定Hook函数, 根据VIRTUAL_METHOD_TYPE我们知道exec的参数从寄存器1开始, 根据{"string"}我们知道参数有1个, 并且是string类型, 这时候我们只需要插入一段字节码在exec的开头:
```
# 获取参数
ALOAD 1
INVOKESTATIC com/security/smith/SmithProbe.trace (Ljava/lang/String;)V
```
两个字节码就可以获取函数调用信息, 第一行将参数推入栈, 第二行调用我们编写好的方法:
```java
public class SmithProbe implements ClassFileTransformer {
    public static void trace(String arg) {

    }
}
```
以上只是一个简单的例子, trace方法我们不能简单的写定参数, 因为每个Hook的函数传进来的参数都不一样. 所以我会在Hook时, 将目标函数的参数推入Object[], 然后传到trace里面来. 另外需要标识是什么类的什么方法调用的trace, 可以在生成字节码时, 给每个调用分配一个id.
```java
public class SmithProbe implements ClassFileTransformer {
    public void trace(int classID, int methodID, Object... args) {

    }
}
```