// =========================================================
// ACCESSIQ - MAIN JAVASCRIPT
// =========================================================

document.addEventListener("DOMContentLoaded", function () {

    // -----------------------------------------------------
    // MOBILE SIDEBAR
    // -----------------------------------------------------

    const sidebar = document.querySelector(".sidebar");
    const menuButton = document.querySelector(".mobile-menu-btn");

    if (menuButton && sidebar) {
        menuButton.addEventListener("click", function () {
            sidebar.classList.toggle("sidebar-open");
        });
    }


    // -----------------------------------------------------
    // CLOSE SIDEBAR WHEN CLICKING A LINK ON MOBILE
    // -----------------------------------------------------

    const sidebarLinks = document.querySelectorAll(".sidebar-link");

    sidebarLinks.forEach(function (link) {
        link.addEventListener("click", function () {

            if (window.innerWidth <= 992 && sidebar) {
                sidebar.classList.remove("sidebar-open");
            }

        });
    });


    // -----------------------------------------------------
    // ACTIVE SIDEBAR LINK
    // -----------------------------------------------------

    const currentPath = window.location.pathname;

    sidebarLinks.forEach(function (link) {

        const linkPath = link.getAttribute("href");

        if (
            linkPath &&
            linkPath !== "#" &&
            currentPath === linkPath
        ) {
            sidebarLinks.forEach(function (item) {
                item.classList.remove("active");
            });

            link.classList.add("active");
        }

    });


    // -----------------------------------------------------
    // NOTIFICATION BUTTON
    // -----------------------------------------------------

    const notificationButton =
        document.querySelector(".notification-btn");

    if (notificationButton) {

        notificationButton.addEventListener("click", function () {

            console.log("AccessIQ notifications clicked.");

        });

    }


    // -----------------------------------------------------
    // SIMPLE FADE-IN EFFECT
    // -----------------------------------------------------

    const animatedElements =
        document.querySelectorAll(".stat-card, .dashboard-card, .security-card");

    animatedElements.forEach(function (element, index) {

        element.style.animationDelay =
            `${index * 0.05}s`;

    });


    // -----------------------------------------------------
    // WINDOW RESIZE
    // -----------------------------------------------------

    window.addEventListener("resize", function () {

        if (window.innerWidth > 992 && sidebar) {
            sidebar.classList.remove("sidebar-open");
        }

    });

});