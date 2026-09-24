package com.maovares.ms_products;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 * Valida que las peticiones que llegan al microservicio traigan el certificado
 * de cliente esperado (enviado por APIM y reenviado por App Service en el
 * header X-ARR-ClientCert). Compara el thumbprint (SHA-1) del certificado
 * recibido contra el valor configurado en la variable de entorno
 * CLIENT_CERT_THUMBPRINT.
 */
@Component
public class ClientCertificateFilter implements Filter {

    private static final String HEADER_NAME = "X-ARR-ClientCert";
    private static final String ENV_VAR_NAME = "CLIENT_CERT_THUMBPRINT";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String expectedThumbprint = System.getenv(ENV_VAR_NAME);
        String certHeaderValue = httpRequest.getHeader(HEADER_NAME);

        if (expectedThumbprint == null || expectedThumbprint.isBlank()) {
            rejectRequest(httpResponse, "Server misconfiguration: " + ENV_VAR_NAME + " not set");
            return;
        }

        if (certHeaderValue == null || certHeaderValue.isBlank()) {
            rejectRequest(httpResponse, "Client Certificate Required");
            return;
        }

        try {
            byte[] certBytes = Base64.getDecoder().decode(certHeaderValue);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) certificateFactory
                    .generateCertificate(new ByteArrayInputStream(certBytes));

            String actualThumbprint = calculateThumbprint(certificate);

            if (!actualThumbprint.equalsIgnoreCase(expectedThumbprint.replace(":", ""))) {
                rejectRequest(httpResponse, "Client Certificate Required");
                return;
            }
        } catch (Exception e) {
            rejectRequest(httpResponse, "Client Certificate Required");
            return;
        }

        chain.doFilter(request, response);
    }

    private String calculateThumbprint(X509Certificate certificate) throws Exception {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] digest = sha1.digest(certificate.getEncoded());
        StringBuilder hex = new StringBuilder();
        for (byte b : digest) {
            hex.append(String.format("%02X", b));
        }
        return hex.toString();
    }

    private void rejectRequest(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("text/html");
        response.getWriter().write("<h1>403 Forbidden</h1><p>" + message + "</p>");
    }
}