package vn.iotstar.exceptions;

import com.nimbusds.jose.JOSEException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private ResponseEntity<Map<String, Object>> buildResponse(HttpStatus status, String message) {
        Map<String, Object> body = new HashMap<>();
        body.put("status", status.value());
        body.put("error", status.getReasonPhrase());
        body.put("message", message);
        return new ResponseEntity<>(body, status);
    }

    /**
     * Sai tên đăng nhập hoặc mật khẩu -> 401 UNAUTHORIZED
     */
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<Map<String, Object>> handleBadCredentialsException(BadCredentialsException ex) {
        return buildResponse(HttpStatus.UNAUTHORIZED, "Sai tên đăng nhập hoặc mật khẩu");
    }

    /**
     * Tài khoản bị vô hiệu hóa hoặc khóa -> 403 FORBIDDEN
     */
    @ExceptionHandler(AccountStatusException.class)
    public ResponseEntity<Map<String, Object>> handleAccountStatusException(AccountStatusException ex) {
        return buildResponse(HttpStatus.FORBIDDEN, "Tài khoản đang bị khóa hoặc bị vô hiệu hóa");
    }

    /**
     * Không có quyền truy cập tài nguyên -> 403 FORBIDDEN
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, Object>> handleAccessDeniedException(AccessDeniedException ex) {
        return buildResponse(HttpStatus.FORBIDDEN, "Bạn không có quyền truy cập vào tài nguyên này");
    }

    /**
     * Lỗi xử lý mã hóa hoặc chữ ký JWT từ Nimbus -> 401 UNAUTHORIZED
     */
    @ExceptionHandler(JOSEException.class)
    public ResponseEntity<Map<String, Object>> handleJOSEException(JOSEException ex) {
        return buildResponse(HttpStatus.UNAUTHORIZED, "Chữ ký hoặc thuật toán mã hóa JWT không hợp lệ");
    }

    /**
     * Lỗi định dạng phân tích JWT từ Nimbus -> 401 UNAUTHORIZED
     */
    @ExceptionHandler(ParseException.class)
    public ResponseEntity<Map<String, Object>> handleParseException(ParseException ex) {
        return buildResponse(HttpStatus.UNAUTHORIZED, "Định dạng token JWT không hợp lệ hoặc đã bị thay đổi");
    }

    /**
     * Các ngoại lệ chung khác -> 500 INTERNAL_SERVER_ERROR
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGeneralException(Exception ex) {
        return buildResponse(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
    }
}
