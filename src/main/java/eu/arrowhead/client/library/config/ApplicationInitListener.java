package eu.arrowhead.client.library.config;


import java.util.Enumeration;
import java.util.NoSuchElementException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Objects;
import java.util.ServiceConfigurationError;

import javax.annotation.PreDestroy;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.annotation.Order;
import org.springframework.util.Assert;

import eu.arrowhead.client.library.ArrowheadService;
import eu.arrowhead.common.CommonConstants;
import eu.arrowhead.common.SSLProperties;
import eu.arrowhead.common.Utilities;
import eu.arrowhead.common.core.CoreSystem;
import eu.arrowhead.common.exception.AuthException;

public abstract class ApplicationInitListener {

	//=================================================================================================
	// members
	
	@Autowired
	private ArrowheadService arrowheadService;
	
	@Autowired
	protected SSLProperties sslProperties;
	
	protected final Logger logger = LogManager.getLogger(ApplicationInitListener.class);
	
	//=================================================================================================
	// methods

	//-------------------------------------------------------------------------------------------------
	@Bean(CommonConstants.ARROWHEAD_CONTEXT)
	@DependsOn("ArrowheadService")
	public Map<String,Object> getArrowheadContext() {
		return new ConcurrentHashMap<>();
	}
	
	//-------------------------------------------------------------------------------------------------
	@EventListener
	@Order(10)
	public void onApplicationEvent(final ContextRefreshedEvent event) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, InterruptedException {
		logger.info("Security mode: {}", getModeString());
		
		if (sslProperties.isSslEnabled()) {
			final KeyStore keyStore = initializeKeyStore();
			checkServerCertificate(keyStore, event.getApplicationContext());
			obtainKeys(keyStore, event.getApplicationContext());
		}
		
		customInit(event);
	}
	
	//-------------------------------------------------------------------------------------------------
	@PreDestroy
	public void destroy() throws InterruptedException {
		customDestroy();
	}	

	//=================================================================================================
	// assistant methods
	
	//-------------------------------------------------------------------------------------------------
	protected void customInit(final ContextRefreshedEvent event) {}
	
	//-------------------------------------------------------------------------------------------------
	protected void customDestroy() {}
	
	//-------------------------------------------------------------------------------------------------
	protected String getModeString() {
		return sslProperties.isSslEnabled() ? "SECURED" : "NOT SECURED";
	}
	
	//-------------------------------------------------------------------------------------------------
	protected void checkCoreSystemReachability(final CoreSystem coreSystem) {
		if (arrowheadService.echoCoreSystem(coreSystem)) {
			logger.info("'{}' core system is reachable.", coreSystem.name());
		} else {
			logger.info("'{}' core system is NOT reachable.", coreSystem.name());
		}
	}
	
	//-------------------------------------------------------------------------------------------------
	private KeyStore initializeKeyStore() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		logger.debug("initializeKeyStore started...");
		Assert.isTrue(sslProperties.isSslEnabled(), "SSL is not enabled.");
		final String messageNotDefined = " is not defined.";
		Assert.isTrue(!Utilities.isEmpty(sslProperties.getKeyStoreType()), CommonConstants.KEYSTORE_TYPE + messageNotDefined);
		Assert.notNull(sslProperties.getKeyStore(), CommonConstants.KEYSTORE_PATH + messageNotDefined);
		Assert.isTrue(sslProperties.getKeyStore().exists(), CommonConstants.KEYSTORE_PATH + " file is not found.");
		Assert.notNull(sslProperties.getKeyStorePassword(), CommonConstants.KEYSTORE_PASSWORD + messageNotDefined);
		
		final KeyStore keystore = KeyStore.getInstance(sslProperties.getKeyStoreType());
		keystore.load(sslProperties.getKeyStore().getInputStream(), sslProperties.getKeyStorePassword().toCharArray());

		return keystore;
	}
	
	//-------------------------------------------------------------------------------------------------
	private void checkServerCertificate(final KeyStore keyStore, final ApplicationContext appContext) {
		logger.debug("checkServerCertificate started...");
		final X509Certificate serverCertificate = getSystemCertFromKeyStore(keyStore);
		final String serverCN = Utilities.getCertCNFromSubject(serverCertificate.getSubjectDN().getName());
		if (!Utilities.isKeyStoreCNArrowheadValid(serverCN)) {
			logger.info("Client CN ({}) is not compliant with the Arrowhead certificate structure, since it does not have 5 parts, or does not end with \"arrowhead.eu\".", serverCN);
			throw new AuthException("Server CN (" + serverCN + ") is not compliant with the Arrowhead certificate structure, since it does not have 5 parts, or does not end with \"arrowhead.eu\".");
		}
		logger.info("Client CN: {}", serverCN);
		
		@SuppressWarnings("unchecked")
		final Map<String,Object> context = appContext.getBean(CommonConstants.ARROWHEAD_CONTEXT, Map.class);
		context.put(CommonConstants.SERVER_COMMON_NAME, serverCN);
	}

	//-------------------------------------------------------------------------------------------------
	public X509Certificate getSystemCertFromKeyStore(final KeyStore keystore) {
		Assert.notNull(keystore, "Key store is not defined.");

        try {
            // the first certificate is not always the end certificate. java does not guarantee the order
			final Enumeration<String> enumeration = keystore.aliases();
            while (enumeration.hasMoreElements()) {
                final Certificate[] chain = keystore.getCertificateChain(enumeration.nextElement());

                if(Objects.nonNull(chain) && chain.length >= 3) {
                    return (X509Certificate) chain[0];
                }
            }
            throw new ServiceConfigurationError("Getting the first cert from keystore failed...");
        } catch (final KeyStoreException | NoSuchElementException ex) {
        	logger.error("Getting the first cert from key store failed...", ex);
            throw new ServiceConfigurationError("Getting the first cert from keystore failed...", ex);
        }
    }
	
	//-------------------------------------------------------------------------------------------------
	private void obtainKeys(final KeyStore keyStore, final ApplicationContext appContext) {
		logger.debug("obtainKeys started...");
		@SuppressWarnings("unchecked")
		final Map<String,Object> context = appContext.getBean(CommonConstants.ARROWHEAD_CONTEXT, Map.class);
		
		context.put(CommonConstants.SERVER_PUBLIC_KEY, getSystemCertFromKeyStore(keyStore).getPublicKey());
		
		final PrivateKey privateKey = getPrivateKey(keyStore, sslProperties.getKeyPassword());
		context.put(CommonConstants.SERVER_PRIVATE_KEY, privateKey);
	}

	//-------------------------------------------------------------------------------------------------
    public PrivateKey getPrivateKey(final KeyStore keystore, final String keyPass) {
        Assert.notNull(keystore, "Key store is not defined.");
        Assert.notNull(keyPass, "Password is not defined.");

        PrivateKey privateKey = null;
        String element;
        try {
            final Enumeration<String> enumeration = keystore.aliases();
            while (enumeration.hasMoreElements()) {
                element = enumeration.nextElement();

                privateKey = (PrivateKey) keystore.getKey(element, keyPass.toCharArray());
                if (privateKey != null) {
                    break;
                }
            }
        } catch (final KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException ex) {
            logger.error("Getting the private key from key store failed...", ex);
            throw new ServiceConfigurationError("Getting the private key from key store failed...", ex);
        }

        if (privateKey == null) {
            throw new ServiceConfigurationError("Getting the private key failed, key store aliases do not identify a key.");
        }

        return privateKey;
    }
}
