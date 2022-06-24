package com.company.keystructure;

/**
 * <p>
 * Record structure to store a trustContent and its relevant DomainKeys
 * as a DomainContent record,
 * and a signature of the DomainContent
 * </p>
 * @param domainContent the content of the domain, as a DomainContent, such as the trust and domain keys
 * @param signature the signature of the domain content as a GeneralSignature
 * @param domainId unique domain id
 */
public record Domain(DomainContent domainContent, GeneralSignature signature, int domainId) {

}
