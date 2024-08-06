function openShowRequestList() {
    document.getElementById('requestListoverlay').classList.add('visible');
    document.getElementById('requestList').classList.add('visible');
    document.getElementById('contactMe').classList.add('hide');
    document.getElementById('dashboardFooter').classList.add('hide');
}

function closeShowRequestList() {
    document.getElementById('requestListoverlay').classList.remove('visible');
    document.getElementById('requestList').classList.remove('visible');
    document.getElementById('contactMe').classList.remove('hide');
    document.getElementById('dashboardFooter').classList.remove('hide');
}

function openShowApprovedList() {
    document.getElementById('pendingApprovaloverlay').classList.add('visible');
    document.getElementById('pendingApproval').classList.add('visible');
    document.getElementById('contactMe').classList.add('hide');
    document.getElementById('dashboardFooter').classList.add('hide');
}

function closeShowApprovedList() {
    document.getElementById('pendingApprovaloverlay').classList.remove('visible');
    document.getElementById('pendingApproval').classList.remove('visible');
    document.getElementById('contactMe').classList.remove('hide');
    document.getElementById('dashboardFooter').classList.remove('hide');
}

function openToApproveList() {
    document.getElementById('ApprovedVisitorsoverlay').classList.add('visible');
    document.getElementById('ApprovedVisitors').classList.add('visible');
    document.getElementById('contactMe').classList.add('hide');
    document.getElementById('dashboardFooter').classList.add('hide');
    document.getElementById('gatePassReminder').classList.remove('show');
    document.getElementById('visitorReminder').classList.remove('show');
}

function closeToApproveList() {
    document.getElementById('ApprovedVisitorsoverlay').classList.remove('visible');
    document.getElementById('ApprovedVisitors').classList.remove('visible');
    document.getElementById('contactMe').classList.remove('hide');
    document.getElementById('dashboardFooter').classList.remove('hide');
}

function openArrivedList() {
    document.getElementById('arrivedOverlay').classList.add('visible');
    document.getElementById('arrivedVisitors').classList.add('visible');
    document.getElementById('contactMe').classList.add('hide');
    document.getElementById('dashboardFooter').classList.add('hide');
}

function closeArrivedList() {
    document.getElementById('arrivedOverlay').classList.remove('visible');
    document.getElementById('arrivedVisitors').classList.remove('visible');
    document.getElementById('contactMe').classList.remove('hide');
    document.getElementById('dashboardFooter').classList.remove('hide');
}

function openReports() {
    document.getElementById('reportOverlay').classList.add('visible');
    document.getElementById('reportButtons').classList.add('visible');
    document.getElementById('contactMe').classList.add('hide');
    document.getElementById('dashboardFooter').classList.add('hide');
}

function closeReports() {
    document.getElementById('reportOverlay').classList.remove('visible');
    document.getElementById('reportButtons').classList.remove('visible');
    document.getElementById('contactMe').classList.remove('hide');
    document.getElementById('dashboardFooter').classList.remove('hide');
}

function openVisitorReport() {
    document.getElementById('reportOverlay').classList.remove('visible');
    document.getElementById('reportButtons').classList.remove('visible');
    document.getElementById('visitorReportOverlay').classList.add('visible');
    document.getElementById('visitorReportButtons').classList.add('visible');
    document.getElementById('contactMe').classList.add('hide');
    document.getElementById('dashboardFooter').classList.add('hide');
}

function closeVisitorReport() {
    document.getElementById('visitorReportOverlay').classList.remove('visible');
    document.getElementById('visitorReportButtons').classList.remove('visible');
    document.getElementById('contactMe').classList.remove('hide');
    document.getElementById('dashboardFooter').classList.remove('hide');
}

function openEmployeeGatePassReport() {
    document.getElementById('reportOverlay').classList.remove('visible');
    document.getElementById('reportButtons').classList.remove('visible');
    document.getElementById('gatePassReportOverlay').classList.add('visible');
    document.getElementById('gatePassReportButtons').classList.add('visible');
    document.getElementById('contactMe').classList.add('hide');
    document.getElementById('dashboardFooter').classList.add('hide');
}

function closeEmployeeGatePassReport() {
    document.getElementById('gatePassReportOverlay').classList.remove('visible');
    document.getElementById('gatePassReportButtons').classList.remove('visible');
    document.getElementById('contactMe').classList.remove('hide');
    document.getElementById('dashboardFooter').classList.remove('hide');
}

function openGatePassListReport() {
    document.getElementById('reportOverlay').classList.remove('visible');
    document.getElementById('reportButtons').classList.remove('visible');
    document.getElementById('gatePassListReportOverlay').classList.add('visible');
    document.getElementById('gatePassListReportButtons').classList.add('visible');
    document.getElementById('contactMe').classList.add('hide');
    document.getElementById('dashboardFooter').classList.add('hide');
}

function closeGatePassListReport() {
    document.getElementById('gatePassListReportOverlay').classList.remove('visible');
    document.getElementById('gatePassListReportButtons').classList.remove('visible');
    document.getElementById('contactMe').classList.remove('hide');
    document.getElementById('dashboardFooter').classList.remove('hide');
}

function openVisitors() {
    document.getElementById('visitorsOverlay').classList.add('visible');
    document.getElementById('visitorsList').classList.add('visible');
    document.getElementById('contactMe').classList.add('hide');
    document.getElementById('dashboardFooter').classList.add('hide');
}

function closeVisitors() {
    document.getElementById('visitorsOverlay').classList.remove('visible');
    document.getElementById('visitorsList').classList.remove('visible');
    document.getElementById('contactMe').classList.remove('hide');
    document.getElementById('dashboardFooter').classList.remove('hide');
}

function openRequestGatePassList() {
    document.getElementById('requestGatePassListOverlay').classList.add('visible');
    document.getElementById('requestGatePassList').classList.add('visible');
    document.getElementById('contactMe').classList.add('hide');
    document.getElementById('dashboardFooter').classList.add('hide');
    document.getElementById('gatePassReminder').classList.remove('show');
    document.getElementById('visitorReminder').classList.remove('show');
}

function closeRequestGatePassList() {
    document.getElementById('requestGatePassListOverlay').classList.remove('visible');
    document.getElementById('requestGatePassList').classList.remove('visible');
    document.getElementById('contactMe').classList.remove('hide');
    document.getElementById('dashboardFooter').classList.remove('hide');
}

function openApprovedGatePassList() {
    document.getElementById('approveGatePassListOverlay').classList.add('visible');
    document.getElementById('approveGatePassList').classList.add('visible');
    document.getElementById('contactMe').classList.add('hide');
    document.getElementById('dashboardFooter').classList.add('hide');
}

function closeApprovedGatePassList() {
    document.getElementById('approveGatePassListOverlay').classList.remove('visible');
    document.getElementById('approveGatePassList').classList.remove('visible');
    document.getElementById('contactMe').classList.remove('hide');
    document.getElementById('dashboardFooter').classList.remove('hide');
}

function openConfirmedGatePassList() {
    document.getElementById('confirmedGatePassListOverlay').classList.add('visible');
    document.getElementById('confirmedGatePassList').classList.add('visible');
    document.getElementById('contactMe').classList.add('hide');
    document.getElementById('dashboardFooter').classList.add('hide');
}

function closeConfirmedGatePassList() {
    document.getElementById('confirmedGatePassListOverlay').classList.remove('visible');
    document.getElementById('confirmedGatePassList').classList.remove('visible');
    document.getElementById('contactMe').classList.remove('hide');
    document.getElementById('dashboardFooter').classList.remove('hide');
}

function openDepartedGatePassList() {
    document.getElementById('departedGatePassListOverlay').classList.add('visible');
    document.getElementById('departedGatePassList').classList.add('visible');
    document.getElementById('contactMe').classList.add('hide');
    document.getElementById('dashboardFooter').classList.add('hide');
}

function closeDepartedGatePassList() {
    document.getElementById('departedGatePassListOverlay').classList.remove('visible');
    document.getElementById('departedGatePassList').classList.remove('visible');
    document.getElementById('contactMe').classList.remove('hide');
    document.getElementById('dashboardFooter').classList.remove('hide');
}

window.onload = function() {
    // Show visitor reminder if it exists
    if (document.getElementById('visitorReminder')) {
        setTimeout(function() {
            document.getElementById('visitorReminder').classList.add('show');
        }, 2000);
    }

    // Show gate pass reminder if it exists
    if (document.getElementById('gatePassReminder')) {
        // Check if visitor reminder exists and adjust position accordingly
        if (document.getElementById('visitorReminder')) {
            document.getElementById('gatePassReminder').style.bottom = '100px';
        }
        setTimeout(function() {
            document.getElementById('gatePassReminder').classList.add('show');
        }, 2000);
    }
};

function closeVisitorReminder() {
    document.getElementById('visitorReminder').classList.remove('show');
    // Adjust gate pass reminder position if visitor reminder is closed
    if (document.getElementById('gatePassReminder')) {
        document.getElementById('gatePassReminder').style.bottom = '32px';
    }
}

function closeGatePassReminder() {
    document.getElementById('gatePassReminder').classList.remove('show');
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