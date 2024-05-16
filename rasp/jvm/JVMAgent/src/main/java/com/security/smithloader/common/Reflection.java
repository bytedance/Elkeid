package com.security.smithloader.common;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/**
 * Reflection utils
 */
public class Reflection {

    /**
     * get object field
     *
     * @param object
     * @param fieldName
     * @return Object
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
     * get super class field
     *
     * @param object
     * @param fieldName
     * @return Object
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
     * get super super class field
     *
     * @param object
     * @param fieldName
     * @return Object
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
     * get Object static field
     *
     * @param clazz
     * @param fieldName
     * @return Object
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
     * get object static method
     *
     * @param clazz      Class
     * @param methodName
     * @param argTypes 
     * @param args       
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
     * get object method
     *
     * @param object
     * @param methodName
     * @param argTypes
     * @param args       
     * @return Object
     */
    public static Object invokeMethod(Object object, String methodName, Class<?>[] argTypes, Object... args) {
        try {
            Method method = object.getClass().getMethod(methodName, argTypes);
            method.setAccessible(true);
            return method.invoke(object, args);
        } catch (InvocationTargetException e) {
            if (e.getCause() instanceof SecurityException) {
                SecurityException securityException = (SecurityException) e.getCause();
                throw securityException;
            } 
        } catch(Throwable e) {
        }

        return null;
    }

    /**
     * get super 
     *
     * @param object
     * @param methodName
     * @param argTypes 
     * @param args     
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
