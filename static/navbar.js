function toggleDropdown(id) {
    const dropdown = document.getElementById(id);
    if (dropdown) {
        dropdown.classList.toggle('show');
    }
}

document.addEventListener('click', function (event) {
    const dropdowns = document.querySelectorAll('.dropdown-menu');
    dropdowns.forEach(dropdown => {
        if (!dropdown.contains(event.target) && !event.target.matches('.dropdown-toggle')) {
            dropdown.classList.remove('show');
        }
    });
});


document.querySelectorAll('input[name="timeframe"]').forEach((radio) => {
    radio.addEventListener('change', function () {
        if (this.id === 'day') {
            console.log('Day data loaded');
        } else if (this.id === 'month') {
            console.log('Month data loaded');
        }
    });
});

window.onload = function() {
    var inputValue = document.getElementById("visitorNo").value;
    document.getElementById("navVisitorNo").innerText = inputValue;
    
    var inputGatePassNo = document.getElementById("gatePassId").value;
    document.getElementById("navGatePassNo").innerText = inputGatePassNo;
};