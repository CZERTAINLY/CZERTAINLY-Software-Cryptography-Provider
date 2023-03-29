package com.czertainly.cp.soft.util;

import com.czertainly.api.model.client.attribute.RequestAttributeDto;
import com.czertainly.api.model.common.attribute.v2.content.BooleanAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContent;
import com.czertainly.api.model.common.collection.DigestAlgorithm;
import com.czertainly.api.model.common.collection.RsaSignatureScheme;
import com.czertainly.api.model.connector.cryptography.operations.CipherDataRequestDto;
import com.czertainly.api.model.connector.cryptography.operations.DecryptDataResponseDto;
import com.czertainly.api.model.connector.cryptography.operations.data.CipherRequestData;
import com.czertainly.api.model.connector.cryptography.operations.data.CipherResponseData;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.cp.soft.attribute.EcdsaKeyAttributes;
import com.czertainly.cp.soft.attribute.RsaKeyAttributes;
import com.czertainly.cp.soft.dao.entity.KeyData;
import com.czertainly.cp.soft.exception.NotSupportedException;
import org.apache.commons.lang.NotImplementedException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.security.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

public class DecryptionUtil {

    private static ASN1ObjectIdentifier contentEncAlg = SMIMECapability.dES_CBC;
    public static final String ATTRIBUTE_IS_CMS_NAME = "data_isCms";

    public static DecryptDataResponseDto decrypt(CipherDataRequestDto request, KeyData key) {
        List<RequestAttributeDto> attributes = request.getCipherAttributes();
        List<BooleanAttributeContent> isCms = AttributeDefinitionUtils.getAttributeContent(ATTRIBUTE_IS_CMS_NAME, attributes, BooleanAttributeContent.class);
        if(isCms.size() == 1 && isCms.get(0).getData()) {
            return decryptCms(request, key);
        }
        throw new NotImplementedException("Requested operation is not implemented");
    }

    public static DecryptDataResponseDto decryptCms(CipherDataRequestDto request, KeyData key) {
        Iterator<CipherRequestData> cipherRequestDataIterator = request.getCipherData().stream().iterator();
        DecryptDataResponseDto responseDto = new DecryptDataResponseDto();
        List<CipherResponseData> responseDataList = new ArrayList<>();
        while (cipherRequestDataIterator.hasNext()) {
            try {
                CMSEnvelopedData ed = new CMSEnvelopedData(cipherRequestDataIterator.next().getData());
                contentEncAlg = ed.getContentEncryptionAlgorithm().getAlgorithm();
                RecipientInformationStore recipients = ed.getRecipientInfos();
                Collection<RecipientInformation> c = recipients.getRecipients();
                Iterator<RecipientInformation> it = c.iterator();
                byte[] decBytes = null;
                while (it.hasNext()) {
                    RecipientInformation recipient = it.next();
                    JceKeyTransEnvelopedRecipient rec = new JceKeyTransEnvelopedRecipient(KeyStoreUtil.getPrivateKey(key));
                    rec.setProvider(BouncyCastleProvider.PROVIDER_NAME);
                    rec.setContentProvider(BouncyCastleProvider.PROVIDER_NAME);
                    rec.setMustProduceEncodableUnwrappedKey(true);
                    decBytes = recipient.getContent(rec);
                    CipherResponseData cipherResponseData = new CipherResponseData();
                    cipherResponseData.setData(decBytes);
                    responseDataList.add(cipherResponseData);
                }
            } catch (Exception e) {
                throw new IllegalArgumentException("Unable to decrypt the CMS data. Error is " + e.getMessage());
            }
        }
        responseDto.setDecryptedData(responseDataList);
        return responseDto;
    }
}
