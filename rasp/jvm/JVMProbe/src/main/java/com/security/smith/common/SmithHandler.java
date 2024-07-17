package com.security.smith.common;

import java.net.URL;
import java.sql.Ref;

import com.security.smith.client.message.ClassFilter;
import com.security.smith.log.SmithLogger;

import javassist.CtClass;

public class SmithHandler {
    /**
     * 
     *
     * @param clazz     
     * @param classFilter
     */
    public static void queryClassFilter(Class<?> clazz, ClassFilter classFilter) {
        try {
            if (clazz != null && classFilter != null) {
                classFilter.setClassName(clazz.getName());
                classFilter.setInterfacesName(SmithHandler.getInterfaces(clazz));
                
                classFilter.setClassPath(SmithHandler.getClassPath(clazz));
                classFilter.setClassLoaderName(SmithHandler.getClassLoader(clazz));

                try {
                        
                    Class<?> superClass = clazz.getSuperclass();
                    if (superClass != null) {
                        String superClassName = superClass.getName();
                        classFilter.setParentClassName(superClassName);
                        ClassLoader parentClassLoader = superClass.getClassLoader();
                        if (parentClassLoader != null) {
                            classFilter.setParentClassLoaderName(parentClassLoader.getClass().getName());
                        }
                    }
                } catch (Exception e) {

                }

            }
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
    }

    /**
     * get classloader
     *
     * @param clazz 
     * @return String  
     */
    public static String getClassLoader(Class<?> clazz) {
        try {
            ClassLoader loader = clazz.getClassLoader();
            if (loader != null) {
                return loader.getClass().getName();    
            }
            
        } catch (Exception e) {

        }
        return "";
    }

     /**
     * get superclass name
     *
     * @param clazz     
     * @return String   
     */
    public static String getSuperClass(Class<?> clazz) {
        try {
            Class<?> superClass = clazz.getSuperclass();
            if (superClass != null) {
                return superClass.getName();
            }
        } catch (Exception e) {
            // TODO: handle exception
        }
        return "";
    }

     /**
     * get class path
     *
     * @param clazz 
     * @return String  
     */
    public static String getClassPath(Class<?> clazz) {
        try {
            return clazz.getProtectionDomain().getCodeSource().getLocation().getPath();
        } catch (Exception e) {
            // TODO: handle exception
        }
        return "";
    }

     /**
     * get CtClass interfaces
     *
     * @param cla    
     * @return String   
     */
    public static String getCtClassInterfaces(CtClass cla) {
        String interfacesName = "";
        try {
            if (cla != null) {
                CtClass[] interfaces = cla.getInterfaces();
                for (CtClass iface : interfaces) {
                    interfacesName += iface.getName() + ",";
                }
                if (interfacesName.length() > 0) {
                    interfacesName = interfacesName.substring(0, interfacesName.length() - 1);
                }
            }
        } catch (Exception e) {
            //SmithLogger.exception(e);
        }
        return interfacesName;
    }

     /**
     * get CtClass path
     *
     * @param cla      
     * @return String
     */
    public static String getCtClassPath(CtClass cla) {
        String path = "";
        try {
            if (cla != null) {
                URL classFileUrl = cla.getURL();
                if (classFileUrl != null) {
                    path = classFileUrl.getPath();
                    if (!path.isEmpty() && path.startsWith("file:")) {
                        path = path.substring(5);
                        if (path.contains("jar!")) {
                            path =  path.substring(0, path.indexOf("jar!") + 3);
                        }
                    }
                }
            }
        } catch (Exception e) {
            // SmithLogger.exception(e);
        }
        return path;
    }

     /**
     * get class interfaces
     *
     * @param clazz   
     * @return String  
     */
    public static String getInterfaces(Class<?> clazz) {
        String interfacesName = "";
        try {
            if (clazz != null) {
                for (Class<?> iface: clazz.getInterfaces()) {
                    interfacesName += iface.getName() + ",";
                }
                if (interfacesName.length() > 0) {
                    interfacesName = interfacesName.substring(0, interfacesName.length() - 1);
                }
            }
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
        return interfacesName;
    }

    /**
     * 
     *
     * @param clazz 
     * @return boolean
     */
    public static boolean checkSuperServlet(Class<?> clazz) {
        try {
			if (clazz != null) {
				Class<?> superClazz = clazz.getSuperclass();
				if (superClazz != null) {
					String clsName = superClazz.getName();
                    clsName.replace(".", "/");
					if (checkInterfaceNeedTran(clsName)) {
                        return true;
					}
				}
			}
		} catch (Exception e) {
            SmithLogger.exception(e);
		}

		return false;
    }

    /**
     * 
     *
     * @param clazz   
     * @return boolean
     */
    private static boolean checkServletInterface(Class<?> clazz) {

		try {
			if (clazz != null) {
				Class<?>[] interFaces = clazz.getInterfaces();
				if (interFaces != null) {
					for (Class<?> cls : interFaces) {
						String clsName = cls.getName();
                        clsName.replace(".", "/");
						if (checkInterfaceNeedTran(clsName)) {
                            return true;
                        }
				    }
			    }
            }
		} catch (Exception e) {
            SmithLogger.exception(e);
		}

		return false;
	}

    public static boolean checkInterfaceNeedTran(String interfaceName) {
        if (interfaceName == null) {
            return false;
        }
        boolean ret = false;
        switch (interfaceName) {
            case "org/springframework/web/servlet/HandlerInterceptor":
            case "javax/servlet/Servlet":
            case "javax/servlet/Filter":
            case "javax/servlet/ServletRequestListener":
            case "jakarta/servlet/Servlet":
            case "jakarta/servlet/Filter":
            case "jakarta/servlet/ServletRequestListener":
            case "javax/websocket/Endpoint":
            case "org/apache/tomcat/util/threads/ThreadPoolExecutor":
            case "org/apache/coyote/UpgradeProtocol":
                ret = true;
                break;
            default:
                break;
        }
        return ret;
    }

    /**
     * 
     *
     * @param clazz     
     * @return boolean
     */
    private static boolean checkProxyClazz(Class<?> clazz) {

		try {
			if (clazz != null) {
				Class<?> superClazz = clazz.getSuperclass();
				if (superClazz != null) {
					String clsName = superClazz.getName();

					if ("java.lang.reflect.Proxy".equals(clsName)) {
						return true;
					}
				}
			}
		} catch (Exception e) {
		}

		return false;
	}

    /**
     * 
     *
     * @param clazz    
     * @return boolean
     */
    private static boolean checkClassIsExisted(Class<?> clazz) {
		boolean bExisted = true;
		try {
			if (clazz != null) {
				//check the class is created from jsp
				ClassLoader clazzLoader = clazz.getClassLoader();
				String classLoaderName;
				if (clazzLoader != null) {
					classLoaderName = clazzLoader.getClass().getName();
					if(classLoaderName != null && classLoaderName.contains("JasperLoader")){
						return false;
					}
				}
				// normal check
				String clazzName = clazz.getName().replace(".", "/");
				URL path = null;
				try {
					path = clazz.getResource("/" + clazzName + ".class");
				} catch (Exception e) {
					SmithLogger.exception(e);
				}
				if (path == null) {
					bExisted = false;
				}
			}
		} catch (Exception e) {
			SmithLogger.exception(e);
		}
		return bExisted;
	}

    /**
     * 
     *
     * @param clazz 
     * @return boolean
     */
    public static boolean checkClassMemshell(Class<?> clazz) {
        if (clazz == null)
            return false;
        try {
            if (checkServletInterface(clazz) || checkSuperServlet(clazz)) {
                if (!checkProxyClazz(clazz) && !checkClassIsExisted(clazz)) {
                    return true;
                }
            }
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
        return false;
    }
}
