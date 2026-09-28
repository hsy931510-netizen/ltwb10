package vn.iotstar.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AuthController {

    /**
     * Trả về trang đăng nhập login.html
     */
    @GetMapping("/login")
    public String login() {
        return "login";
    }

    /**
     * Trả về trang thông tin người dùng profile.html
     */
    @GetMapping("/user/profile")
    public String profile() {
        return "profile";
    }
}
