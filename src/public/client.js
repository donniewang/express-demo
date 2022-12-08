$(function () {
  $.get("/users", function (users) {
    users.forEach(function (user) {
      $("<li></li>")
        .text(user.username + " " + user.email)
        .appendTo("ul#users");
    });
  });
});
