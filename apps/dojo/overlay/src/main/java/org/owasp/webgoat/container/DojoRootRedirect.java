/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 Code to Cloud Security Dojo authors
 * SPDX-License-Identifier: MIT
 */
package org.owasp.webgoat.container;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.stereotype.Component;

@Component
public final class DojoRootRedirect
    implements WebServerFactoryCustomizer<TomcatServletWebServerFactory> {

  @Override
  public void customize(TomcatServletWebServerFactory factory) {
    factory.addEngineValves(new RootRedirectValve());
  }

  private static final class RootRedirectValve extends ValveBase {

    private RootRedirectValve() {
      super(true);
    }

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
      if ("/".equals(request.getRequestURI())) {
        response.setStatus(HttpServletResponse.SC_FOUND);
        response.setHeader("Location", "/WebGoat/");
        return;
      }
      getNext().invoke(request, response);
    }
  }
}
