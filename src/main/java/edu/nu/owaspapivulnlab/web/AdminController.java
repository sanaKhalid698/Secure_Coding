package edu.nu.owaspapivulnlab.web;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    // FIXED(API7: Security Misconfiguration)
    // Added method-level authorization to ensure only ADMIN users can access system metrics.
    // Previously, this could be exposed if route matching or configuration allowed open access.
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/metrics")
    public Map<String, Object> metrics() {
        RuntimeMXBean rt = ManagementFactory.getRuntimeMXBean();
        Map<String, Object> metricsMap = new HashMap<>();
        metricsMap.put("uptimeMs", rt.getUptime());
        metricsMap.put("javaVersion", System.getProperty("java.version"));
        metricsMap.put("threads", ManagementFactory.getThreadMXBean().getThreadCount());
        return metricsMap;
    }
}
