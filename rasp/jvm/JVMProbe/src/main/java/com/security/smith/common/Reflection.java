package com.security.smith.common;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 *  reflection utils
 */
public class Reflection {

    /**
     *
     *
     * @param object    
     * @param fieldName 
     * @return 
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
     * 
     *
     * @param object    
     * @param fieldName 
     * @return 
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
     * 
     *
     * @param object    
     * @param fieldName 
     * @return 
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
     * 
     *
     * @param clazz   
     * @param fieldName 
     * @return 
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
     * get static method
     *
     * @param clazz      
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
        } catch (Throwable t) {  
        }

        return null;
    }

        /**
     * get object method no return
     *
     * @param object     
     * @param methodName 
     * @param argTypes   
     * @param args      
     * @return Object
     */
    public static boolean invokeMethodNoReturn(Object object, String methodName, Class<?>[] argTypes, Object... args) {
        try {
            Method method = object.getClass().getDeclaredMethod(methodName, argTypes);
            method.setAccessible(true);
            method.invoke(object, args);

            return true;
        } catch (Throwable t) {
        }

        return false;
    }

    /**
     * get super method 
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

     /**
     * get super method no return
     *
     * @param object     
     * @param methodName 
     * @param argTypes   
     * @param args      
     * @return boolean
     */

    public static boolean invokeSuperMethodNoReturn(Object object, String methodName, Class<?>[] argTypes, Object... args) {
        try {
            Method method = object.getClass().getSuperclass().getDeclaredMethod(methodName, argTypes);
            method.setAccessible(true);
            method.invoke(object, args);
            return true;
        } catch (Throwable t) {
        }

        return false;
    }

         /**
     * get super super method
     *
     * @param object    
     * @param methodName 
     * @param argTypes   
     * @param args       
     * @return boolean
     */

    public static boolean invokeSuperSuperMethodNoReturn(Object object, String methodName, Class<?>[] argTypes, Object... args) {
        try {
            Method method = object.getClass().getSuperclass().getSuperclass().getDeclaredMethod(methodName, argTypes);
            method.setAccessible(true);
            method.invoke(object, args);
            return true;
        } catch (Throwable t) {
        }

        return false;
    }
}
