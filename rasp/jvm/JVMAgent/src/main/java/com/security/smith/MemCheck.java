package com.security.smith;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryPoolMXBean;
import java.lang.management.MemoryUsage;
import com.sun.management.OperatingSystemMXBean;
import java.util.List;

public class MemCheck {
    public static long getHeapMemoryFree() {
        MemoryMXBean memoryMXBean = ManagementFactory.getMemoryMXBean();
        MemoryUsage memoryUsage = memoryMXBean.getHeapMemoryUsage();
        return (memoryUsage.getMax() - memoryUsage.getUsed()) / 1048576L;
    }
  
    public static long getMetaMemoryFree() {
        List<MemoryPoolMXBean> memoryMXBeans = ManagementFactory.getMemoryPoolMXBeans();
        if (memoryMXBeans == null) {
            return -1L;
        }
        MemoryPoolMXBean metaBean = null;
        for (MemoryPoolMXBean bean : memoryMXBeans) {
            String beanName = bean.getName();
            if (beanName == null || beanName.length() == 0) {
                continue;
            }
            if (beanName.toLowerCase().contains("metaspace")) {
                metaBean = bean;
                break;
            } 
            if (beanName.toLowerCase().contains("perm gen")) {
                metaBean = bean;
                break;
            } 
        } 
        if (metaBean == null) {
            return -1L;
        }
        MemoryUsage memoryUsage = metaBean.getUsage();
        return (memoryUsage.getMax() - memoryUsage.getUsed()) / 1048576L;
    }

    public static long getSystemMemoryFree() {
        OperatingSystemMXBean osBean = (OperatingSystemMXBean)ManagementFactory.getOperatingSystemMXBean();
        long freeMem = osBean.getFreePhysicalMemorySize();
        return  freeMem / 1048576L;
    }

    public static int getSystemCpuLoad() {
        OperatingSystemMXBean osBean = (OperatingSystemMXBean)ManagementFactory.getOperatingSystemMXBean();
        return (int)(osBean.getSystemCpuLoad() * 100.0D);
    }
}
