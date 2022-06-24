package com.company.keystructure;

import java.io.Serializable;

/**
 * <p>
 * This structure stores the trustContent and domainKeys
 * without a signature
 * </p>
 * @param trust the trust as Trust, to store
 * @param domainKeys the domainKeys as DomainKeys, to store
 */
public record DomainContent(Trust trust, DomainKeys domainKeys) implements Serializable {

}