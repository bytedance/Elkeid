package com.security.smith.common;

import java.net.URL;
import java.sql.Ref;

import com.security.smith.client.message.ClassFilter;
import com.security.smith.log.SmithLogger;

import javassist.CtClass;

public class SmithHandler {
    /**
     * 查询Class的元数据信息
     *
     * @param clazz     Class对象
     * @param classFilter 保存类的元数据信息
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
     * 获取类的加载器名
     *
     * @param clazz     Class对象
     * @return String   加载器名
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
     * 获取父类名
     *
     * @param clazz     Class对象
     * @return String   父类名
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
     * 获取类文件路径
     *
     * @param clazz     Class对象
     * @return String   class文件路径
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
     * 获取CtClass的接口
     *
     * @param cla    CtClass对象
     * @return String   接口名
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
     * 获取CtClass的路径
     *
     * @param cla      CtClass对象
     * @return String  文件路径
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
     * 获取类实现的接口名
     *
     * @param clazz     Class对象
     * @return String   接口名
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
     * 检查父类是否为特定类
     *
     * @param clazz     Class对象
     * @return boolean
     */
    public static boolean checkSuperServlet(Class<?> clazz) {
        try {
			if (clazz != null) {
				Class<?> superClazz = clazz.getSuperclass();
				if (superClazz != null) {
					String clsName = superClazz.getName();

					if ("javax.servlet.http.HttpServlet".equals(clsName)
                            || ("org.apache.catalina.valves.ValveBase".equals(clsName))) {
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
     * 检查类实现的接口是否为特定接口类
     *
     * @param clazz     Class对象
     * @return boolean
     */
    private static boolean checkServletInterface(Class<?> clazz) {

		try {
			if (clazz != null) {
				Class<?>[] interFaces = clazz.getInterfaces();
				if (interFaces != null) {
					for (Class<?> cls : interFaces) {
						String clsName = cls.getName();
						if (clsName.startsWith("javax.servlet.")) {
							if (clsName.endsWith(".Filter")
                                    || clsName.endsWith(".Servlet")
								    || clsName.endsWith(".ServletRequestListener")) {
								return true;
							}
					    } else if (clsName.equals("org.springframework.web.servlet.HandlerInterceptor")) {
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

    /**
     * 检查类是否为Proxy类
     *
     * @param clazz     Class对象
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
     * 检查类是否存在磁盘上
     *
     * @param clazz     Class对象
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
     * 检查类是否为内存马
     *
     * @param clazz     Class对象
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
