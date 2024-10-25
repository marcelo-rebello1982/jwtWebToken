package br.com.cadastroit.services.utils;

public class Constants {

	/* CORE BUSINESS */

	public static final String CORE_DEFAULT_DATE_TIME_PATTERN = "yyyy-MM-dd HH:mm:ss";
	public static final String CORE_SPRING_DATA_MAX_PAGE_SIZE = "spring.data.max.page.size";

	public static final int BASE_NR = 3;


	public static final String SERVER_SPRING_PROFILE_ENV = "spring.profiles.active";
	public static final String SERVER_PORT = "server.port";
	public static final String SERVER_CONTEXT_PATH = "server.servlet.context-path";
	public static final String SERVER_PATH_FISICO_TMP = "server.path.fisico";
	public static final String SERVER_PATH_VIRTUAL_TMP = "server.path.virtual";
	public static final String INFO_APP_VERSION = "info.app.version";

	public static final String SECURITY_CAS_URL_PREFIX_ENV = "cas.url.prefix";
	public static final String SECURITY_APP_SERVICE_HOME_ENV = "app.service.home";
	public static final String SECURITY_APP_ADMIN_USER_NAME_ENV = "app.admin.userName";
	public static final String SECURITY_APP_ADMIN_USER_ID_ENV = "app.admin.userId";
	public static final String SECURITY_COOKIE_AUTHENTICACAO_BASE = "baseOuCNPJ";

	/* SECURITY */

	/* API */
	public static final String URL_API_INTERNA_COMPRAS = "client.api.url.compras";
	public static final String URL_API_INTERNA_ESTOQUE = "client.api.url.estoque";
	public static final String URL_API_INTERNA_ERP = "client.api.url.erp";
	public static final String URL_API_INTERNA_CONCILIADOR = "client.api.url.conciliadorcartoes";
	public static final String URL_API_INTERNA_VOPAYMENTS = "client.api.url.vopayments";
	public static final String URL_API_INTERNA_PDVMANAGER = "client.api.url.pdvmanager";

	/* Services */
	public static final String CLIENT_REDIRECT_URL_COMPRAS = "client.url.compras";
	public static final String CLIENT_REDIRECT_URL_ESTOQUE = "client.url.estoque";
	public static final String URL_INTERNA_VPSA_STORE_SERVICES = "client.api.url.store";
	public static final String URL_APPS_API = "client.api.url.apps";

	/* JMS */
	public static final String JMS_ACTIVEMQ_BROKER_URL = "spring.activemq.broker-url";

	/* AWS */
	public static final String AWS_ACCESSKEY = "aws.accesskey";
	public static final String AWS_SECRETKEY = "aws.secretkey";

	/* Mercado Pago */
	public static final String URL_API_MERCADO_PAGO = "mercado.pago.url";

	/* Sellbie */
	public static final String URL_API_SELLBIE = "sellbie.url";

	/* MAIL */
	public static final String MAIL_SMTP = "spring.mail.host";
	public static final String MAIL_PORT = "spring.mail.port";
	public static final String MAIL_USER = "spring.mail.username";
	public static final String MAIL_PASS = "spring.mail.password";

	/* APPS OAUTH */
	public static final String APPS_OAUTH_CLIENT_ID = "apps.oauth.client.id";
	public static final String APPS_OAUTH_CLIENT_SECRET = "apps.oauth.client.secret";

	/* SCHEDULING */
	public static final String SCHEDULING_ENABLED = "scheduling.enabled";

	/* DFe */
	public static final String DFE_AMBIENTE = "dfe.ambiente";

}
