package com.czertainly.cp.soft.config;

import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.format.FormatterRegistry;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebAppConfig implements WebMvcConfigurer {
    @Override
    public void addFormatters(FormatterRegistry registry) {
        registry.addConverter(new Converter<String, KeyAlgorithm>() {
            @Override
            public KeyAlgorithm convert(String source) {
                return KeyAlgorithm.findByCode(source);
            }
        });
    }
}
