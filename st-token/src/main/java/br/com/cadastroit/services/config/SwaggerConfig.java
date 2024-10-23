package br.com.cadastroit.services.config;

import java.util.Arrays;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurationSupport;

import com.google.common.collect.Lists;

import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.builders.ResponseMessageBuilder;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.ApiKey;
import springfox.documentation.service.AuthorizationScope;
import springfox.documentation.service.BasicAuth;
import springfox.documentation.service.Contact;
import springfox.documentation.service.ResponseMessage;
import springfox.documentation.service.SecurityReference;
import springfox.documentation.service.SecurityScheme;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spi.service.contexts.SecurityContext;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

@Configuration
@EnableSwagger2
public class SwaggerConfig extends WebMvcConfigurationSupport{

	private final ResponseMessage R_MESSAGE_200 = new ResponseMessageBuilder().code(200).message("Sucesso").build();
	private final ResponseMessage R_MESSAGE_201 = new ResponseMessageBuilder().code(200).message("Registro criado").build();
	private final ResponseMessage R_MESSAGE_204 = new ResponseMessageBuilder().code(204).message("Registro atualizado, movido ou excluido").build();
	private final ResponseMessage R_MESSAGE_401 = new ResponseMessageBuilder().code(401).message("Acesso nao autorizado").build();
	private final ResponseMessage R_MESSAGE_403 = new ResponseMessageBuilder().code(403).message("Sem os privilegios necessarios para acessar este recurso").build();
	private final ResponseMessage R_MESSAGE_404 = new ResponseMessageBuilder().code(404).message("Nao encontrado").build();
	private final ResponseMessage R_MESSAGE_500 = new ResponseMessageBuilder().code(500).message("Erro interno no servidor").build();
	
	@Bean
	public Docket databaseAPI() {
		return new Docket(DocumentationType.SWAGGER_2)
				.useDefaultResponseMessages(false)
				.globalResponseMessage(RequestMethod.GET, Arrays.asList(R_MESSAGE_200, R_MESSAGE_401, R_MESSAGE_403, R_MESSAGE_404, R_MESSAGE_500))
				.globalResponseMessage(RequestMethod.POST, Arrays.asList(R_MESSAGE_201, R_MESSAGE_401, R_MESSAGE_403, R_MESSAGE_404, R_MESSAGE_500))
				.globalResponseMessage(RequestMethod.PUT, Arrays.asList(R_MESSAGE_204, R_MESSAGE_401, R_MESSAGE_403, R_MESSAGE_404, R_MESSAGE_500))
				.globalResponseMessage(RequestMethod.DELETE, Arrays.asList(R_MESSAGE_204, R_MESSAGE_401, R_MESSAGE_403, R_MESSAGE_404, R_MESSAGE_500))
				.select()
				.apis(RequestHandlerSelectors.basePackage("br.com.cadastroit.services.web.controller"))
				.paths(PathSelectors.any())
				.build()
				.securitySchemes(Lists.newArrayList(apiKey(),basicScheme()))
	            .securityContexts(Lists.newArrayList(securityContext()))
				.apiInfo(metaData());	   
	}
	
	private ApiInfo metaData() {
		return new ApiInfoBuilder()
				  .title("ST Token - API Restfull (Gestao de usuarios com JSON Web Token)")
				  .description("\"ST JSON WEB TOKEN\"")
				  .version("1.0.0")
				  .license("Apache License 2.0.0")
				  .licenseUrl("https://www.apache.org/licenses/LICENSE-2.0")
				  .contact(new Contact("Marcelo Paulo R Martins", "https://marcelo-rebello.com.br", "contato@marcelo-rebello.com.br"))
				  .build();
	}
	
	@Bean
	public SecurityContext securityContext() {
		return SecurityContext.builder()
	            .securityReferences(defaultAuth())
	            .forPaths(PathSelectors.regex("/.*"))
	            .build();
	}
	
	
	@Override
	protected void addResourceHandlers(ResourceHandlerRegistry registry) {
		registry.addResourceHandler("swagger-ui.html")
				.addResourceLocations("classpath:/META-INF/resources/");
		
		registry.addResourceHandler("/webjars/**")
				.addResourceLocations("classpath:/META-INF/resources/webjars/");
	}
	
	private List<SecurityReference> defaultAuth() {
		AuthorizationScope authorizationScope
	            = new AuthorizationScope("global", "accessEverything");
	    AuthorizationScope[] authorizationScopes = new AuthorizationScope[1];
	    authorizationScopes[0] = authorizationScope;
	    return Lists.newArrayList(
	            new SecurityReference("JWT", authorizationScopes));
	}

	private SecurityScheme basicScheme(){
		return new BasicAuth("basicAuth");
	}
	
	private ApiKey apiKey() {
	    return new ApiKey("JWT", "Authorization", "header");
	}
}
