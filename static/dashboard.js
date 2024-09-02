function toggleSubMenu(id) {
    var submenu = document.getElementById(id);
    submenu.style.display = submenu.style.display === 'block' ? 'none' : 'block';
}

function loadContent(url) {
    event.preventDefault();
    fetch(url, { headers: { "X-Requested-With": "XMLHttpRequest" } })
        .then(response => response.text())
        .then(data => {
            document.getElementById('content').innerHTML = data;
            history.pushState(null, '', url);
        })
        .catch(error => console.log('Error loading content:', error));
}

let currentPopup = null;

function togglePopup(popupId) {
    // Close the current popup if it's open and different from the new one
    if (currentPopup && currentPopup !== popupId) {
        document.getElementById(currentPopup).classList.remove('visible');
    }

    // Show the new popup or close it if the same popup is clicked again
    const popup = document.getElementById(popupId);
    if (popup.classList.contains('visible')) {
        popup.classList.remove('visible');
        currentPopup = null;
    } else {
        popup.classList.add('visible');
        currentPopup = popupId;
    }

    // Toggle visibility of the common elements
    const hideElements = popup.classList.contains('visible');
    document.getElementById('contactMe').classList.toggle('hide', hideElements);
    document.getElementById('dashboardFooter').classList.toggle('hide', hideElements);
}

function closeCurrentPopup() {
    // Close the current popup
    if (currentPopup) {
        document.getElementById(currentPopup).classList.remove('visible');
        currentPopup = null;

        // Show the common elements
        document.getElementById('contactMe').classList.remove('hide');
        document.getElementById('dashboardFooter').classList.remove('hide');
    }
}

window.onload = function() {
    let reminders = [
        'visitorReminder',
        'gatePassReminder',
        'visitorGateReminder',
        'gatePassGateReminder',
        'approvedGatePassReminder'
    ];

    let visibleReminders = reminders.filter(id => document.getElementById(id));

    visibleReminders.forEach((id, index) => {
        setTimeout(function() {
            document.getElementById(id).classList.add('show');
            document.getElementById(id).style.top = `${10 + index * 70}px`;
        }, 2000);
    });
};

function closeReminder(id) {
    document.getElementById(id).classList.remove('show');
    adjustReminderPositions();
}

function adjustReminderPositions() {
    let reminders = [
        'visitorReminder',
        'gatePassReminder',
        'visitorGateReminder',
        'gatePassGateReminder',
        'approvedGatePassReminder'
    ];

    let visibleReminders = reminders.filter(id => {
        let element = document.getElementById(id);
        return element && element.classList.contains('show');
    });

    visibleReminders.forEach((id, index) => {
        document.getElementById(id).style.top = `${10 + index * 70}px`;
    });
}

function closeVisitorReminder() {
    closeReminder('visitorReminder');
}

function closeGatePassReminder() {
    closeReminder('gatePassReminder');
}

function closeVisitorGateReminder() {
    closeReminder('visitorGateReminder');
}

function closeGatePassGateReminder() {
    closeReminder('gatePassGateReminder');
}

function closeApprovedGatePassReminder() {
    closeReminder('approvedGatePassReminder');
}

function openHelp() {
    document.getElementById('helpMenuOverlay').classList.add('visible');
    document.getElementById('helpMenu').classList.add('visible');
    document.getElementById('contactMe').classList.add('hide');
    document.getElementById('dashboardFooter').classList.add('hide');
}

function closeHelp() {
    document.getElementById('helpMenuOverlay').classList.remove('visible');
    document.getElementById('helpMenu').classList.remove('visible');
    document.getElementById('contactMe').classList.remove('hide');
    document.getElementById('dashboardFooter').classList.remove('hide');
}

document.addEventListener("DOMContentLoaded", function () {
    openWindow(1);
});

function openWindow(index) {
    for (let i = 1; i <= 6; i++) {
        const windowElement = document.getElementById(`window${i}`);
        const buttonElement = document.getElementById(`button${i}`);
        
        if (i === index) {
            windowElement.classList.add('visible');
            buttonElement.classList.add('activeButton');
        } else {
            windowElement.classList.remove('visible');
            buttonElement.classList.remove('activeButton');
        }
    }
}

document.getElementById("fullscreenTrigger").addEventListener("click", function() {
    const fullscreenImage = document.getElementById("fullscreenImage");
    const fullscreenOverlay = document.getElementById("fullscreenOverlay");

    fullscreenImage.src = this.src;
    fullscreenOverlay.style.display = "flex";
});

function closeFullscreen() {
    document.getElementById("fullscreenOverlay").style.display = "none";
}

document.addEventListener("DOMContentLoaded", function () {
    // ... (your existing code)

    // Add the event listener for the search box
    const searchInput = document.getElementById("visitor-search");
    searchInput.addEventListener("input", function () {
        const searchTerm = this.value.trim().toLowerCase();
        performSearch(searchTerm);
    });
});

document.addEventListener("DOMContentLoaded", function () {
    const searchInput = document.getElementById('visitor-search');
    const searchResults = document.getElementById('search-results');
    const allVisitors = document.querySelectorAll('#search-results li');

    searchInput.addEventListener('input', function () {
        const searchTerm = searchInput.value.toLowerCase();

        // Show only the matching visitors based on the search term
        allVisitors.forEach(function (visitor) {
            const visitorNumber = visitor.querySelector('span:first-child').textContent.toLowerCase();
            const shouldShow = visitorNumber.includes(searchTerm);
            visitor.style.display = shouldShow ? 'block' : 'none';
        });
    });
});

document.addEventListener('DOMContentLoaded', function () {
    const visitorItems = document.querySelectorAll('.visitor-item');

    visitorItems.forEach(item => {
        item.addEventListener('mouseover', function (event) {
            const detailBox = this.querySelector('.detail-box');
            const rect = this.getBoundingClientRect();
            const detailBoxHeight = detailBox.offsetHeight;

            // Reset any inline styles first
            detailBox.style.top = '';
            detailBox.style.bottom = '';
            
            // Check if detail box would go beyond the viewport bottom
            if (rect.bottom + detailBoxHeight > window.innerHeight) {
                detailBox.style.bottom = '100%';
            } else {
                detailBox.style.top = '100%';
            }

            // Adjust left position if it overflows the right side of the viewport
            if (rect.right + detailBox.offsetWidth > window.innerWidth) {
                detailBox.style.left = 'auto';
                detailBox.style.right = '0';
            } else {
                detailBox.style.left = '0';
                detailBox.style.right = 'auto';
            }
        });
    });
});