-libraryjars  <java.home>/jmods(!**.jar;!module-info.class)

-printmapping build/libs/proguard.map

-keepparameternames
-renamesourcefileattribute SourceFile
-keepattributes Exceptions,InnerClasses,Signature,Deprecated, SourceFile,LineNumberTable,*Annotation*,EnclosingMethod

-keepclasseswithmembernames,includedescriptorclasses class * {
    native <methods>;
}

-keepclassmembers,allowoptimization enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

-keepclassmembers class * implements java.io.Serializable {
    static final long serialVersionUID;
    private static final java.io.ObjectStreamField[] serialPersistentFields;
    private void writeObject(java.io.ObjectOutputStream);
    private void readObject(java.io.ObjectInputStream);
    java.lang.Object writeReplace();
    java.lang.Object readResolve();
}

-obfuscationdictionary build/dict/dict.txt
-classobfuscationdictionary build/dict/dict.txt
-packageobfuscationdictionary build/dict/dict.txt

-dontwarn rasp.io.netty.**
-keep class rasp.io.netty.** {*;}

-dontwarn rasp.com.lmax.disruptor.**
-keep class rasp.com.lmax.disruptor.** {*;}

-keep class rasp.com.fasterxml.jackson.** {*;}

-keepclassmembers class * extends rasp.com.fasterxml.jackson.databind.ser.std.StdSerializer {
    <init>(...);
}

-keepclassmembers class * extends rasp.com.fasterxml.jackson.databind.deser.std.StdDeserializer {
    <init>(...);
}

-keep class com.security.smith.processor.* {*;}
-keep class com.security.smith.type.* {*;}

-keep class com.security.smith.SmithAgent {*;}

-keep class com.security.smith.SmithProbe {
    public void detect(int, int, java.lang.Object[]);
    public void trace(int, int, java.lang.Object[], java.lang.Object, boolean);
    public static com.security.smith.SmithProbe getInstance();
}