WGET = wget --no-check-certificate
KEYTOOL = keytool
JAVAC = javac

KS_PWD = password

CC_ROOTS = \
    https://www.digicert.com/CACerts/BaltimoreCyberTrustRoot.crt \
    https://pki.multicert.com/cert/MULTICERT_CA/mca_001_2.cer

CC_STATE_ROOTS = \
    https://www.scee.gov.pt/media/1709/ECRaizEstado.crt

CC_CERTS = 1 2 3 4 # Add more number if needed
CC_CERT_FILES = $(foreach n, $(CC_CERTS), Cartao-de-Cidadao-00$(n).cer)

CC_SIGN_CERTS = 01 02 03 04 05 06 07 08 09 10 11 12 13 14 # Add more number if needed
CC_SIGN_CERT_FILES = $(foreach n, $(CC_SIGN_CERTS), EC-de-Assinatura-Digital-Qualificada-do-Cartao-de-Cidadao-00$(n).cer)

CC_AUTH_CERTS = 01 02 03 04 05 06 07 08 09 10 11 12 13 14 # Add more number if needed
CC_AUTH_CERT_FILES = $(foreach n, $(CC_AUTH_CERTS), EC-de-Autenticacao-do-Cartao-de-Cidadao-00$(n).cer)

CC_ALL_CERT_FILES = \
	$(foreach c, $(CC_ROOTS), $(notdir $c)) \
	$(foreach c, $(CC_STATE_ROOTS), $(notdir $c)) \
	$(CC_CERT_FILES) \
	$(CC_SIGN_CERT_FILES) \
	$(CC_AUTH_CERT_FILES)
CCKS = CC_KS

all: CCkeystore

CCkeystore:
	@for i in $(CC_ROOTS) $(CC_STATE_ROOTS); do \
            alias=`basename $$i | \
			sed -e s/.cer//g | \
			sed -e s/.der//g | \
			sed -e s/.crt//g | \
			sed -e s/-//g | \
			tr A-Z a-z`; \
	    echo "Check alias $$alias"; \
	    $(KEYTOOL) -exportcert -alias $$alias -storepass $(KS_PWD) -noprompt -keystore $(CCKS) > /dev/null || \
	    ( \
	    	$(WGET) $$i; \
		touch newCert; \
	    ) \
	done
	@for i in $(CC_CERT_FILES); do \
            alias=`basename $$i | \
			sed -e s/.cer//g | \
			sed -e s/.der//g | \
			sed -e s/.crt//g | \
			sed -e s/-//g | \
			tr A-Z a-z`; \
	    echo "Check alias $$alias"; \
	    $(KEYTOOL) -exportcert -alias $$alias -storepass $(KS_PWD) -noprompt -keystore $(CCKS) > /dev/null || \
	    ( \
		u=`echo $$i | sed -e s/-/%20/g`; \
	    	$(WGET) https://pki.cartaodecidadao.pt/publico/certificado/cc_ec_cidadao/$$u; \
		s=`echo $$i | sed -e s/-/\ /g`; \
		mv "$$s" $$i; \
		touch newCert; \
	    ) \
	done
	@for i in $(CC_SIGN_CERT_FILES); do \
            alias=`basename $$i | \
			sed -e s/.cer//g | \
			sed -e s/.der//g | \
			sed -e s/.crt//g | \
			sed -e s/-//g | \
			tr A-Z a-z`; \
	    echo "Check alias $$alias"; \
	    $(KEYTOOL) -exportcert -alias $$alias -storepass $(KS_PWD) -noprompt -keystore $(CCKS) > /dev/null || \
	    ( \
		u=`echo $$i | sed -e s/-/%20/g`; \
	    	$(WGET) https://pki.cartaodecidadao.pt/publico/certificado/cc_ec_cidadao_assinatura/$$u; \
		s=`echo $$i | sed -e s/-/\ /g`; \
		mv "$$s" $$i; \
		touch newCert; \
	    ) \
	done
	@for i in $(CC_AUTH_CERT_FILES); do \
            alias=`basename $$i | \
			sed -e s/.cer//g | \
			sed -e s/.der//g | \
			sed -e s/.crt//g | \
			sed -e s/-//g | \
			tr A-Z a-z`; \
	    echo "Check alias $$alias"; \
	    $(KEYTOOL) -exportcert -alias $$alias -storepass $(KS_PWD) -noprompt -keystore $(CCKS) > /dev/null || \
	    ( \
		u=`echo $$i | sed -e s/-/%20/g`; \
	    	$(WGET) https://pki.cartaodecidadao.pt/publico/certificado/cc_ec_cidadao_autenticacao/$$u; \
		s=`echo $$i | sed -e s/-/\ /g`; \
		mv "$$s" $$i; \
		touch newCert; \
	    ) \
	done
	@if [ -f newCert ]; then \
	    for i in $(CC_ALL_CERT_FILES); do \
		[ -f $$i ] && \
		( \
		    a=`echo $$i | \
			sed -e s/.cer//g | \
			sed -e s/.der//g | \
			sed -e s/.crt//g | \
			sed -e s/-//g`; \
		    echo -n "Certificate with alias" $$a ": "; \
		    $(KEYTOOL) -importcert  -storepass $(KS_PWD) -noprompt -keystore $(CCKS) -file $$i -alias "$$a"; \
		) \
	    done; \
	    rm newCert; \
	    rm *.crt *.cer; \
	fi
