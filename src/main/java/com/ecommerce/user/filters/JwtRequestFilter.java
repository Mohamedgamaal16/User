package com.ecommerce.user.filters;

import com.ecommerce.user.services.jwt.UserDetailesSerivceImpl;
import com.ecommerce.user.utils.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtRequestFilter extends OncePerRequestFilter {

    private final UserDetailesSerivceImpl userDetailsService;
    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        // استخراج الهيدر Authorization
        String authHeader = request.getHeader("Authorization");
        String token = null;
        String userName = null;

        // التأكد أن الهيدر يحتوي على Bearer token
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
            userName = jwtUtil.extractUserName(token);
        }

        // التحقق من عدم وجود Authentication مسبقاً في الـ Context
        if (userName != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(userName);

            // التحقق من صلاحية الـ Token
            if (jwtUtil.validateToken(token, userDetails)) {
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // حفظ الـ Authentication في Security Context
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        // استكمال تنفيذ باقي الفلاتر في السلسلة
        filterChain.doFilter(request, response);
    }
}
