package br.com.cadastroit.services.config;

import br.com.cadastroit.services.config.security.JwtAuthenticationEntryPoint;
import br.com.cadastroit.services.config.security.JwtRequestFilter;
import br.com.cadastroit.services.config.security.model.UserDetailsJwt;
import br.com.cadastroit.services.config.security.model.UserGroupJwt;

import com.mongodb.ConnectionString;
import com.mongodb.MongoClientSettings;
import com.mongodb.MongoCredential;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import lombok.RequiredArgsConstructor;
import org.bson.UuidRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Base64;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	public final static String USERNAME = "admin-view";
	public final static String PASSWORD = "admin-42xy-userDefault";
	
	private String pathFilter = System.getenv("pathFilter") != null ? System.getenv("pathFilter") : "authenticate" ;

	@Value("${spring.data.mongodb.database}")
	private String database;

	@Value("${spring.data.mongodb.host}")
	private String host;

	@Value("${spring.data.mongodb.password}")
	private String password;

	@Value("${spring.data.mongodb.username}")
	private String username;
	private JwtRequestFilter jwtRequestFilter;
	private MongoTemplate mongoTemplate;

	@Primary
	@Bean
	public MongoTemplate mongoTemplate(){
		MongoClientSettings mongoClientSettings = MongoClientSettings.builder()
				.applyToSslSettings(ssl->{
					ssl.enabled(false).build();
				})
				.applyConnectionString(new ConnectionString("mongodb://"+username+":"+password+"@"+host+":27017/"+database))
				.applyToConnectionPoolSettings(pool->{
					pool.maxSize(100)
						.minSize(10)
						.maxConnectionIdleTime(55, TimeUnit.SECONDS)
						.maxConnectionLifeTime(60, TimeUnit.SECONDS)
						.build();
				}).uuidRepresentation(UuidRepresentation.STANDARD)
				.credential(MongoCredential.createCredential(username, database, password.toCharArray()))
				.build();
		MongoClient client = MongoClients.create(mongoClientSettings);
		if(this.mongoTemplate == null){
			this.mongoTemplate = new MongoTemplate(client, database);
		}
		return mongoTemplate;
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	private JwtRequestFilter jwtRequestFilter() throws Exception{
		if(this.jwtRequestFilter == null){
			this.jwtRequestFilter = JwtRequestFilter.builder().mongoTemplate(this.mongoTemplate()).passwordEncoder(this.passwordEncoder()).build();
		}
		return this.jwtRequestFilter;
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
        http.csrf(csrf -> csrf.ignoringAntMatchers("/" + pathFilter + "/**", "/security/**"));
		http.addFilterBefore(this.jwtRequestFilter(), UsernamePasswordAuthenticationFilter.class);
        http.authorizeRequests(requests -> 
   			requests
                .antMatchers("/eureka/**",
                        "/login",
                        "/webjars/**",
                        "/swagger-resources/**",
                        "/swagger-ui.html",
                        "/swagger-ui.html/**",
                        "/v2/api-docs")
                .permitAll())
        		.authorizeRequests(requests ->
        			requests
						.antMatchers(HttpMethod.POST,
						"/" + pathFilter + "/jwtauthentication/auth/user/token",
						"/" + pathFilter + "/jwtauthentication/auth/user/create-user", 
						"/" + pathFilter + "/jwtauthentication/auth/user/ccrypt-decrypt",
						"/" + pathFilter + "/checkvaliditytoken",
						"/" + pathFilter + "/recovery",
						"/" + pathFilter + "/create-user",
						"/" + pathFilter + "/crypt-password")
						.permitAll())
   						.authorizeRequests(requests ->
   					requests
   						.anyRequest()
   						.authenticated())
   						.exceptionHandling(
   					handling -> 
   					handling
   						.authenticationEntryPoint(JwtAuthenticationEntryPoint.builder().build()))
   						.sessionManagement(	management ->
                	management
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        
        		createSystemDefaultUser();
	}

	private void createSystemDefaultUser(){
		try {
			UserGroupJwt userGroupJwt = null;
			String group = "admin-roles";
			Criteria criteria = Criteria.where("group").is(group);
			Query query = new Query(criteria).limit(1);
			List<UserGroupJwt> collection = this.mongoTemplate.find(query, UserGroupJwt.class);
			if (collection.isEmpty()) {
				userGroupJwt = new UserGroupJwt();
				userGroupJwt.setGroup("admin-roles");
				this.mongoTemplate.save(userGroupJwt);

				UserGroupJwt userGroupJwtUser = new UserGroupJwt();
				userGroupJwtUser.setGroup("user-roles");
				this.mongoTemplate.save(userGroupJwtUser);
			}

			Criteria criteriaUser = Criteria.where("username").is(USERNAME);
			Query queryUser = new Query(criteriaUser);
			Long count = this.mongoTemplate().count(queryUser, UserDetailsJwt.class);
			if (count == 0) {
				UserDetailsJwt userDetailsJwt = new UserDetailsJwt();
				userDetailsJwt.setUsername(USERNAME);
				userDetailsJwt.setPassword(this.passwordEncoder().encode(Base64.getEncoder().encodeToString(PASSWORD.getBytes())));
				userDetailsJwt.setUserGroupJwt(userGroupJwt);
				this.mongoTemplate.save(userDetailsJwt);
			}
		} catch (Exception ex){

		}
	}
}
