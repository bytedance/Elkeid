package com.security.smithloader.common;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/**
 * 反射工具类
 */
public class Reflection {

    /**
     * 反射获取对象的field
     *
     * @param object    对象
     * @param fieldName 字段名称
     * @return 值
     */
    public static Object getField(Object object, String fieldName) {
        try {
            Field field = object.getClass().getDeclaredField(fieldName);
            field.setAccessible(true);
            return field.get(object);
        } catch (Throwable t) {  
        }

        return null;
    }

    /**
     * 反射获取对象父类的field
     *
     * @param object    对象
     * @param fieldName 字段名称
     * @return 值
     */
    public static Object getSuperField(Object object, String fieldName) {
        try {
            Field field = object.getClass().getSuperclass().getDeclaredField(fieldName);
            field.setAccessible(true);
            return field.get(object);
        } catch (Throwable t) {

        }

        return null;
    }


    /**
     * 反射获取对象父类的父类的field
     *
     * @param object    对象
     * @param fieldName 字段名称
     * @return 值
     */
    public static Object getSuperParentField(Object object, String fieldName) {
        try {
            Field field = object.getClass().getSuperclass().getSuperclass().getDeclaredField(fieldName);
            field.setAccessible(true);
            return field.get(object);
        } catch (Throwable t) {

        }

        return null;
    }

    /**
     * 反射获取对象的field
     *
     * @param clazz   Class
     * @param fieldName 字段名称
     * @return 值
     */
    public static Object getStaticField(Class<?> clazz, String fieldName) {
        try {
            Field field = clazz.getDeclaredField(fieldName);
            field.setAccessible(true);
            return field.get(null);
        } catch (Throwable t) {
        }

        return null;
    }

    /**
     * 反射调用类的静态方法
     *
     * @param clazz      Class
     * @param methodName 类的方法名称
     * @param argTypes   参数类型
     * @param args       参数
     * @return Object
     */
    public static Object invokeStaticMethod(Class<?> clazz, String methodName, Class<?>[] argTypes, Object... args) {
        try {
            Method method = clazz.getMethod(methodName, argTypes);
            method.setAccessible(true);
            return method.invoke(null, args);
        } catch (Throwable t) {  
        }

        return null;
    }

    /**
     * 反射调用类的方法
     *
     * @param object     类的对象
     * @param methodName 类的方法名称
     * @param argTypes   参数类型
     * @param args       参数
     * @return Object
     */
    public static Object invokeMethod(Object object, String methodName, Class<?>[] argTypes, Object... args) {
        try {
            Method method = object.getClass().getMethod(methodName, argTypes);
            method.setAccessible(true);
            return method.invoke(object, args);
        } catch (Throwable t) {  
        }

        return null;
    }

    /**
     * 反射调用父类的方法
     *
     * @param object     类的对象
     * @param methodName 类的方法名称
     * @param argTypes   参数类型
     * @param args       参数
     * @return Object
     */
    public static Object invokeSuperMethod(Object object, String methodName, Class<?>[] argTypes, Object... args) {
        try {
            Method method = object.getClass().getSuperclass().getMethod(methodName, argTypes);
            method.setAccessible(true);
            return method.invoke(object, args);
        } catch (Throwable t) {
        }

        return null;
    }
}
