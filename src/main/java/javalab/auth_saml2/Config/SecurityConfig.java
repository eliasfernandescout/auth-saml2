package javalab.auth_saml2.Config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;

import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

    public SecurityConfig(RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {
        this.relyingPartyRegistrationRepository = relyingPartyRegistrationRepository;
    }

    @Bean
    public org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver relyingPartyRegistrationResolver() {
        return new org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver(relyingPartyRegistrationRepository);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter filter = new org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter(relyingPartyRegistrationResolver(), new OpenSamlMetadataResolver());

        http.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .saml2Login(Customizer.withDefaults())
                .saml2Logout(Customizer.withDefaults())
                .addFilterBefore(filter, org.springframework.security.saml2.provider.service.web.authentication.Saml2WebSsoAuthenticationFilter.class);

        return http.build();
    }
}