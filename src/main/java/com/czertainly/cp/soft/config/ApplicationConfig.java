package com.czertainly.cp.soft.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

import javax.xml.ws.BindingProvider;
import java.net.URL;

@Configuration
@EnableJpaAuditing
@ComponentScan(basePackages = "com.czertainly.cp.soft")
public class ApplicationConfig {
    private static final Logger logger = LoggerFactory.getLogger(ApplicationConfig.class);


}
