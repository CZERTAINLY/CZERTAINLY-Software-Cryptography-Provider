package com.czertainly.cp.soft.api;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.common.attribute.v2.BaseAttribute;
import com.czertainly.cp.soft.attribute.KeyAttributes;
import com.czertainly.cp.soft.collection.CryptographicAlgorithm;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/v1/cryptographyProvider/callbacks")
public class CallbackController {

    @RequestMapping(
            path = "/keyspec/{algorithm}/attributes",
            method = RequestMethod.GET,
            produces = "application/json"
    )
    public List<BaseAttribute> getKeySpecAttributes(
            @PathVariable CryptographicAlgorithm algorithm) throws NotFoundException {

        switch (algorithm) {
            case RSA:
                return KeyAttributes.getRsaKeySpecAttributes();
            case FALCON:
                return KeyAttributes.getFalconKeySpecAttributes();
            case ECDSA:
                throw new NotFoundException("Algorithm not supported");
            default:
                throw new NotFoundException("Algorithm not supported");
        }

    }


}
