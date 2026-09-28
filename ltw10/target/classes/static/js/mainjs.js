$(document).ready(function () {
    // 1. Khi trang load: nếu tồn tại phần tử #profile (tức đang ở trang profile.html)
    if ($('#profile').length > 0) {
        var token = localStorage.token || localStorage.getItem('token');

        if (!token) {
            alert("Sorry, you are not logged in.");
            window.location.href = '/login';
            return;
        }

        $.ajax({
            url: '/users/me',
            type: 'GET',
            headers: {
                'Authorization': 'Bearer ' + token
            },
            success: function (data) {
                // Hiển thị fullName vào #profile
                $('#profile').html('<h4>Xin chào: ' + data.fullName + '</h4><p class="text-muted">Email: ' + data.email + '</p>');
                // Gán src cho #images nếu có ảnh
                if (data.images) {
                    $('#images').attr('src', data.images);
                }
            },
            error: function (xhr, status, error) {
                alert("Sorry, you are not logged in.");
                localStorage.clear();
                window.location.href = '/login';
            }
        });
    }

    // 2. Khi click nút #Login (ở trang login.html)
    $('#Login').click(function (e) {
        e.preventDefault();
        var email = $('#email').val();
        var password = $('#password').val();

        if (!email || !password) {
            alert("Vui lòng nhập đầy đủ Email và Password!");
            return;
        }

        var loginPayload = {
            email: email,
            password: password
        };

        $.ajax({
            url: '/auth/login',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify(loginPayload),
            success: function (data) {
                if (data && data.token) {
                    localStorage.token = data.token;
                    window.location.href = '/user/profile';
                } else {
                    alert("Login Failed");
                }
            },
            error: function (xhr, status, error) {
                alert("Login Failed");
            }
        });
    });

    // 3. Khi click nút #logout (ở trang profile.html)
    $('#logout').click(function (e) {
        e.preventDefault();
        localStorage.clear();
        window.location.href = '/login';
    });
});
