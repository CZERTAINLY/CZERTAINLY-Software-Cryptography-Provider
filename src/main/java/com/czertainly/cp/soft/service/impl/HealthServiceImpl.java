package com.czertainly.cp.soft.service.impl;

import com.czertainly.api.model.common.HealthDto;
import com.czertainly.api.model.common.HealthStatus;
import com.czertainly.cp.soft.service.HealthService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class HealthServiceImpl implements HealthService {

    private static final Logger logger = LoggerFactory.getLogger(HealthServiceImpl.class);


    @Override
    public HealthDto checkHealth() {
        HealthDto health = new HealthDto();
        //health.setParts(checkDbStatus());

        // set the overall status
        health.setStatus(HealthStatus.OK);
        //for (var entry : health.getParts().entrySet()) {
        //    if (entry.getValue().getStatus() == HealthStatus.NOK) {
        //        health.setStatus(HealthStatus.NOK);
        //        break;
        //    }
        //}
        return health;
    }

}
