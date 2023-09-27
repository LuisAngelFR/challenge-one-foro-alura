package com.alura.foro;

import com.alura.JWTAuthorizationFilter;
import com.alura.modelo.Curso;
import com.alura.modelo.StatusTopico;
import com.alura.modelo.Topico;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.crypto.spec.SecretKeySpec;
import java.sql.*;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

@SpringBootApplication
@RestController
public class ForoInicialApplication implements WebMvcConfigurer {
    private final JWTAuthorizationFilter jwtAuthorizationFilter = new JWTAuthorizationFilter();

    public static void main(String[] args) {
        SpringApplication.run(ForoInicialApplication.class, args);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .addFilterAfter(jwtAuthorizationFilter, UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests()
                .requestMatchers("/login").permitAll()
                .requestMatchers("/swagger-ui/**").permitAll()
                .requestMatchers("/api-docs/**").permitAll()
                .anyRequest().authenticated();
        return http.build();
    }

    @Autowired
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("admin")
                .password("{noop}admin")
                .roles("ADMIN");
    }

    private String generateToken(String username) {
        String token;

        List<GrantedAuthority> grantedAuthorities = AuthorityUtils
                .commaSeparatedStringToAuthorityList("ADMIN");

        JwtBuilder builder = Jwts.builder()
                .setSubject(username)
                .claim("authorities", grantedAuthorities.stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList()))
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
                .signWith(new SecretKeySpec(Objects.requireNonNull(jwtAuthorizationFilter.SECRET), SignatureAlgorithm.HS256.getJcaName()));
        token = builder.compact();

        return token;
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestParam String username, @RequestParam String password) {
        try {
            String token = generateToken(username);
            return ResponseEntity.ok(Map.of("token", token));
        } catch (AuthenticationException e) {
            throw new BadCredentialsException("Invalid username/password supplied");
        }
    }

    @PostMapping("/topicos")
    public Topico crearTopico(@RequestBody @NonNull Topico topicoForm) {
        Connection connection = null;
        try {
            connection = DriverManager.getConnection("jdbc:sqlite:db/foro.db");

            String sql = "INSERT INTO topicos(titulo, mensaje, fecha_creacion, estatus, autor, curso) VALUES(?,?,?,?,?,?)";
            String sqlCurso = "INSERT INTO cursos(nombre, categoria) VALUES(?,?)";

            String titulo = topicoForm.getTitulo();
            String mensaje = topicoForm.getMensaje();
            Date fecha_creacion = new Date(System.currentTimeMillis());
            StatusTopico estatus = StatusTopico.NO_RESPONDIDO;
            String autor = "anonimo";
            String curso = topicoForm.getCurso().getNombre();

            PreparedStatement preparedStatement = connection.prepareStatement(sql);
            preparedStatement.setString(1, titulo);
            preparedStatement.setString(2, mensaje);
            preparedStatement.setDate(3, fecha_creacion);
            preparedStatement.setString(4, estatus.toString());
            preparedStatement.setString(5, autor);
            preparedStatement.setString(6, curso);
            preparedStatement.executeUpdate();

            PreparedStatement preparedStatementCurso = connection.prepareStatement(sqlCurso);
            preparedStatementCurso.setString(1, curso);
            preparedStatementCurso.setString(2, topicoForm.getCurso().getCategoria());
            preparedStatementCurso.executeUpdate();

            connection.close();

            return new Topico(titulo, mensaje, topicoForm.getCurso());

        } catch (Exception e) {
            System.out.println(e.getMessage());
            return null;
        }
    }

    @GetMapping("/topicos")
    public Topico[] getTopicos() {
        Connection connection = null;
        try {
            connection = DriverManager.getConnection("jdbc:sqlite:db/foro.db");

            String sql = "SELECT * FROM topicos";
            String sqlCurso = "SELECT * FROM cursos WHERE nombre = ?";

            PreparedStatement preparedStatement = connection.prepareStatement(sql);
            ResultSet rs = preparedStatement.executeQuery();

            PreparedStatement preparedStatementCurso = connection.prepareStatement(sqlCurso);

            Topico[] topicos = new Topico[100];

            int i = 0;
            while (rs.next()) {
                String titulo = rs.getString("titulo");
                String mensaje = rs.getString("mensaje");
                Curso curso = null;

                preparedStatementCurso.setString(1, rs.getString("curso"));
                ResultSet rsCurso = preparedStatementCurso.executeQuery();
                while (rsCurso.next()) {
                    Long id = rsCurso.getLong("id");
                    String nombre = rsCurso.getString("nombre");
                    String categoria = rsCurso.getString("categoria");
                    curso = new Curso(nombre, categoria);
                    curso.setId(id);
                }

                topicos[i] = new Topico(titulo, mensaje, curso);
                String dateStr = rs.getString("fecha_creacion");
                Date date = new Date(Long.parseLong(dateStr));
                topicos[i].setId(rs.getLong("id"));
                topicos[i].setfechaCreacion(date.toLocalDate().atTime(date.toLocalDate().atStartOfDay().toLocalTime()));
                i++;
            }

            connection.close();

            Topico[] topicosClean = new Topico[i];
            System.arraycopy(topicos, 0, topicosClean, 0, i);
            return topicosClean;

        } catch (Exception e) {
            System.out.println(e.getMessage());
            return null;
        }
    }

    @GetMapping("/topicos/{id}")
    public Topico getTopico(@PathVariable Long id) {
        Connection connection = null;
        try {
            connection = DriverManager.getConnection("jdbc:sqlite:db/foro.db");

            String sql = "SELECT * FROM topicos WHERE id = ?";
            String sqlCurso = "SELECT * FROM cursos WHERE nombre = ?";

            PreparedStatement preparedStatement = connection.prepareStatement(sql);
            preparedStatement.setLong(1, id);
            ResultSet rs = preparedStatement.executeQuery();

            PreparedStatement preparedStatementCurso = connection.prepareStatement(sqlCurso);
            ResultSet rsCurso = preparedStatementCurso.executeQuery();

            Topico topico = null;
            Curso curso = null;

            while (rsCurso.next()) {
                String nombre = rsCurso.getString("nombre");
                String categoria = rsCurso.getString("categoria");
                curso = new Curso(nombre, categoria);
            }

            while (rs.next()) {
                String titulo = rs.getString("titulo");
                String mensaje = rs.getString("mensaje");
                topico = new Topico(titulo, mensaje, curso);
            }

            connection.close();

            return topico;

        } catch (Exception e) {
            System.out.println(e.getMessage());
            return null;
        }
    }

    @PutMapping("/topicos/{id}")
    public Topico updateTopico(@PathVariable Long id, @RequestBody @NonNull Topico topicoForm) {
        Connection connection = null;
        try {
            connection = DriverManager.getConnection("jdbc:sqlite:db/foro.db");

            String sql = "UPDATE topicos SET titulo = ?, mensaje = ? WHERE id = ?";
            String sqlCurso = "UPDATE cursos SET nombre = ?, categoria = ? WHERE nombre = ?";

            String titulo = topicoForm.getTitulo();
            String mensaje = topicoForm.getMensaje();

            PreparedStatement preparedStatement = connection.prepareStatement(sql);
            preparedStatement.setString(1, titulo);
            preparedStatement.setString(2, mensaje);
            preparedStatement.setLong(3, id);
            preparedStatement.executeUpdate();

            PreparedStatement preparedStatementCurso = connection.prepareStatement(sqlCurso);
            preparedStatementCurso.setString(1, topicoForm.getCurso().getNombre());
            preparedStatementCurso.setString(2, topicoForm.getCurso().getCategoria());
            preparedStatementCurso.setString(3, topicoForm.getCurso().getNombre());
            preparedStatementCurso.executeUpdate();

            connection.close();

            return getTopico(id);

        } catch (Exception e) {
            System.out.println(e.getMessage());
            return null;
        }
    }

    @DeleteMapping("/topicos/{id}")
    public Map<String, Boolean> deleteTopico(@PathVariable Long id) {
        Connection connection = null;
        try {
            connection = DriverManager.getConnection("jdbc:sqlite:db/foro.db");

            String sql = "DELETE FROM topicos WHERE id = ?";

            Topico topico = getTopico(id);


            PreparedStatement preparedStatement = connection.prepareStatement(sql);
            preparedStatement.setLong(1, id);
            preparedStatement.executeUpdate();

            connection.close();

            return Map.of("deleted", true);

        } catch (Exception e) {
            System.out.println(e.getMessage());
            return Map.of("deleted", false);
        }
    }
}