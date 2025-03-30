function toggleSubMenu(id) {
    var submenu = document.getElementById(id);
    submenu.style.display =
        submenu.style.display === "block" ? "none" : "block";
}

function loadContent(url) {
    event.preventDefault();
    fetch(url, { headers: { "X-Requested-With": "XMLHttpRequest" } })
        .then((response) => response.text())
        .then((data) => {
            document.getElementById("content").innerHTML = data;
            history.pushState(null, "", url);
        })
        .catch((error) => console.log("Error loading content:", error));
}

let currentPopup = null;

function togglePopup(popupId) {
    if (currentPopup && currentPopup !== popupId) {
        document.getElementById(currentPopup).classList.remove("visible");
    }

    const popup = document.getElementById(popupId);
    if (popup.classList.contains("visible")) {
        popup.classList.remove("visible");
        currentPopup = null;
    } else {
        popup.classList.add("visible");
        currentPopup = popupId;
    }

    const hideElements = popup.classList.contains("visible");
    document.getElementById("contactMe").classList.toggle("hide", hideElements);
    document
        .getElementById("dashboardFooter")
        .classList.toggle("hide", hideElements);
}

function closeCurrentPopup() {
    if (currentPopup) {
        document.getElementById(currentPopup).classList.remove("visible");
        currentPopup = null;

        document.getElementById("contactMe").classList.remove("hide");
        document.getElementById("dashboardFooter").classList.remove("hide");
    }
}

window.onload = function () {
    let reminders = [
        "visitorReminder",
        "gatePassReminder",
        "visitorGateReminder",
        "gatePassGateReminder",
        "approvedGatePassReminder",
    ];

    let visibleReminders = reminders.filter((id) =>
        document.getElementById(id)
    );

    visibleReminders.forEach((id, index) => {
        setTimeout(function () {
            document.getElementById(id).classList.add("show");
            document.getElementById(id).style.top = `${10 + index * 70}px`;
        }, 2000);
    });
};

function closeReminder(id) {
    document.getElementById(id).classList.remove("show");
    adjustReminderPositions();
}

function adjustReminderPositions() {
    let reminders = [
        "visitorReminder",
        "gatePassReminder",
        "visitorGateReminder",
        "gatePassGateReminder",
        "approvedGatePassReminder",
    ];

    let visibleReminders = reminders.filter((id) => {
        let element = document.getElementById(id);
        return element && element.classList.contains("show");
    });

    visibleReminders.forEach((id, index) => {
        document.getElementById(id).style.top = `${10 + index * 70}px`;
    });
}

function closeVisitorReminder() {
    closeReminder("visitorReminder");
}

function closeGatePassReminder() {
    closeReminder("gatePassReminder");
}

function closeVisitorGateReminder() {
    closeReminder("visitorGateReminder");
}

function closeGatePassGateReminder() {
    closeReminder("gatePassGateReminder");
}

function closeApprovedGatePassReminder() {
    closeReminder("approvedGatePassReminder");
}

function openHelp() {
    document.getElementById("helpMenuOverlay").classList.add("visible");
    document.getElementById("helpMenu").classList.add("visible");
    document.getElementById("contactMe").classList.add("hide");
    document.getElementById("dashboardFooter").classList.add("hide");
}

function closeHelp() {
    document.getElementById("helpMenuOverlay").classList.remove("visible");
    document.getElementById("helpMenu").classList.remove("visible");
    document.getElementById("contactMe").classList.remove("hide");
    document.getElementById("dashboardFooter").classList.remove("hide");
}

function openSideMenu() {
    document.getElementById("sideMenu").classList.add("sideMenuOpened");
}

function closeSideMenu() {
    document.getElementById("sideMenu").classList.remove("sideMenuOpened");
}
