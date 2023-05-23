# Notes - Privacy System KMS

## General flow

## Client

### Startup process:

> 1. Get Client IP.
> 2. Type Client name.
> 3. Type Server IP to connect to.
> 4. Attempt to establish connection: 
>    - Setup system property.
>    - Setup server registry.
>    - Setup registry lookup.
> 5. Create Client object and subscribe to server.

```mermaid
sequenceDiagram
    Title: Client startup sequence
    participant Client
    participant Server

	Client-->>Client: Get own host ip
    Client->>Client: Type client name
    Client->>Client: Type server ip    

    Client->>Server: Try for connection (RME)
    Server->>Client: Allow comunication (RME)

    Client->>Server: Subscribe Client
    
```

### Client menu:

> Menu:  
> 
> 1. encrypt file with domain. 
> 2. decrypt file with domain.
> 3. Go back.

```mermaid
	sequenceDiagram
		participant Client
		participant ServerInterface
		
		Client->>ServerInterface: 
```

## Operator

### Startup process:

> 1. Get Operator IP.
> 2. Type Client name.
> 3. Type Server IP to connect to.
> 4. Attempt to establish connection: 
>    - Setup system property.
>    - Setup server registry.
>    - Setup registry lookup.
> 5. Create Operator object and subscribe to server.

```mermaid
sequenceDiagram
    Title: Operator startup sequence
    participant Operator
    participant Server

    Operator-->>Operator: Get own host ip
    Operator->>Operator: Type operator name
    Operator->>Operator: Type server ip    

    Operator->>Server: Try for connection (RME)
    Server->>Operator: Allow comunication (RME)

    Operator->>Server: Subscribe Operator
```


### Operator menu:

```mermaid
sequenceDiagram
	Title Operator menu
	participant Operator
	participant ServerInterface

	opt Visualize
	Operator-->>ServerInterface: showTrust
	Operator-->>ServerInterface: showDomains
	Operator-->>ServerInterface: showOperatorKeyPair
	Operator-->>ServerInterface: showHsmPublicKeys
	Operator-->>ServerInterface: showHardwareSecurityModules
	note left of showTrust: hello
	end
	opt Trust operations
	Operator-->>ServerInterface: createNewTrust
	Operator-->>ServerInterface: operatorSignTrust
	Operator-->>ServerInterface: createNewDomain
	Operator-->>ServerInterface: createNewHardwareSecurityModule
	end
```


## General functional use

```mermaid
sequenceDiagram
    Title: Interations with HSM
    participant Agent
    participant HSM Cluster

    opt Domain operations
    Agent-->>HSM Cluster: createDomain
    Agent-->>HSM Cluster: verifyDomainSignature
    Agent-->>HSM Cluster: encryptWithDomain
    Agent-->>HSM Cluster: decryptWithDomain
    Agent-->>HSM Cluster: signWithDomain
    end
    opt Trust operations
    Agent-->>HSM Cluster: createTrust
    Agent-->>HSM Cluster: updateTrust
    Agent-->>HSM Cluster: verifyTrustSignature
    end
    opt Nonspecific operations
    Agent-->>HSM Cluster: getPublicKey
    Agent-->>HSM Cluster: getId
    Agent-->>HSM Cluster: getWordlyIdentifier
    end
```

## General structure

Panels
Windows
Client