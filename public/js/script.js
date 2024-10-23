function openNav() {
    document.getElementById("mySidenav").style.width = "250px";
}
  
function closeNav() {
    document.getElementById("mySidenav").style.width = "0";
}

  
function goToHomepage() {
    window.location.href = "/"; // Navigate to the root URL
}

function goToAboutpage() {
    window.location.href = "/about"; // Navigate to the '/about' route
}

function Acceptedride() {
    window.location.href = "/acceptedride"; // Navigate to the '/about' route
}

function goTorideinfopage() {
    window.location.href = "/ride-info"; // Navigate to the '/about' route
}

function goToLoginpage() {
    window.location.href = "/Login"; // Navigate to the '/login' route
}

function goToContactpage() {
    window.location.href = "/contact"; // Navigate to the '/contact' route
}

function goToSignuppage() {
    window.location.href = "/signup"; 
}

function goToDriverLoginpage() {
    window.location.href = "/driverlogin"; 
}

function goToDriverSignuppage() {
    window.location.href = "/driversignup"; 
}

function goToProfilepage() {
    window.location.href = "/profile"; 
}

function goToBookingpage() {
    window.location.href = "/booking"; 
}

function goToDProfile(){
    window.location.href = "/driverprofile";
}

function goToDRides(){
    window.location.href = "/recordinfo";
}

function goToRidersspage(){
    window.location.href = "/records"; 
}
function openNav() {
    var sideNav = document.getElementById("mySidenav");
    sideNav.style.width = "250px";
    // Add a smooth slide-in animation
    sideNav.style.transition = "width 0.5s";
}

function closeNav() {
    var sideNav = document.getElementById("mySidenav");
    sideNav.style.width = "0";
    // Add a smooth slide-out animation
    sideNav.style.transition = "width 0.5s";
}

function setCookie() {
    var u = document.getElementById('uname').value;
    var p = document.getElementById('psw').value;
    document.cookie = "myusername=" + encodeURIComponent(u) + "; path=/";
    document.cookie = "mypassword=" + encodeURIComponent(p) + "; path=/";
}

    function getLocation() {
            if (navigator.geolocation) {
                navigator.geolocation.getCurrentPosition(gotLocation, failedToGet);
            } else {
                alert("Geolocation is not supported by this browser.");
            }
    }

    function gotLocation(position) {
        const geocoder = new google.maps.Geocoder();
        const latlng = {
            lat: position.coords.latitude,
            lng: position.coords.longitude
        };

        geocoder.geocode({ 'location': latlng }, function (results, status) {
            if (status === 'OK') {
                if (results[0]) {
                    const address = results[0].formatted_address;
                    console.log(address)
                    document.querySelector('.autocomplete.source').value = address;
                } else {
                    alert('No results found');
                }
            } else {
                alert('Geocoder failed due to: ' + status);
            }
        });
    }

    function findDriver() {
       window.location.href = '/searching-driver';
    }
    
function failedToGet() {
    alert('Please allow access to your location.');
}

function generateOTP(length) {
    const charset = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    let OTP = '';

    for (let i = 0; i < length; i++) {
        OTP += charset.charAt(Math.floor(Math.random() * charset.length));
    }

    return OTP;
}

function getcookiedata(){
    var user=getCookie('myusername');
    var pwd=getCookie('mypassword');
    document.getElementById('uname').value=user;
    document.getElementById('psw').value=pwd;
}

function getCookie(name) {
    var cname = name + "=";
    var decodedCookie = decodeURIComponent(document.cookie);
    var ca = decodedCookie.split(';');
    for(var i = 0; i < ca.length; i++) {
        var c = ca[i];
        while (c.charAt(0) == ' ') {
            c = c.substring(1);
        }
        if (c.indexOf(cname) == 0) {
            return c.substring(cname.length, c.length);
        }
    }
    return "";
}


async function fetchBookingsByCity(city) {
    try {
        // Query to find all bookings where the city matches the specified value
        const bookings = await CabBooking.find({ city: city });

        // Check if any bookings were found
        if (bookings.length === 0) {
            console.log(`No bookings found for city: ${city}`);
        } else {
            console.log(`Fetched bookings for city ${city}:`, bookings);
        }
    } catch (error) {
        console.error('Error fetching bookings:', error);
    }
}

async function goto() {
    const citySelect = document.getElementById('city');
    const selectedCity = citySelect.value; // Get the selected value
    console.log(`Selected city: ${selectedCity}`); // Log the selected city

    try {
        const response = await fetch('/search-riderss', {
            method: 'POST',
            headers: {  
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ startLocation: selectedCity }) // Sending the selected city
        });

        if (!response.ok) {
            throw new Error('Network response was not ok');
        }

        const bookings = await response.json();
        displayRides(bookings);
    } catch (error) {
        console.error('Error fetching data:', error);
    }
}

async function fetchBookingsByCity(city) {
    try {
        const bookings = await CabBooking.find({ city: city });

        console.log(`Fetched bookings for city ${city}:`, bookings);
        displayRides(bookings);
    } catch (error) {
        console.error('Error fetching bookings:', error);
    }
}

function gotoRecord() {
    window.location.href = "/records";
}

function gotodriverRecord() {
    window.location.href = "/driverRecord";
}

function displayRides(bookings) {
    const rideInfoDiv = document.querySelector('.users-list'); 
    rideInfoDiv.innerHTML = ''; 

    if (bookings.length === 0) {
        rideInfoDiv.innerHTML = `
        <h1 id="Hell">No Users Available</h1><br>
        <p>Sorry, there are currently no Users available. Please try again later.</p>
    </div>`;
        return;
    }

    bookings.forEach(booking => {
        const rideDetails = `
            <div class="users-list">
                <div class="ride-info">
                <p class="details names"><strong>Name:</strong> ${booking.name}</p>
                <p class="details source"><strong>Source:</strong> ${booking.source}</p>
                <p class="details destination"><strong>Destination:</strong> ${booking.destination}</p>
                <p class="details date"><strong>Date:</strong> ${new Date(booking.date).toLocaleDateString()}</p>
                <a href="#" class="wapis2" onclick="acceptRiderr('${booking._id}')">Accept ride!</a>
            </div>
        `;
        rideInfoDiv.innerHTML += rideDetails;
    });
}

async function acceptRiderr(bookingId) {
    try {
        const response = await fetch('/accept-riderr', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ bookingId }) // Send bookingId to the server
        });

        if (!response.ok) {
            throw new Error('Network response was not ok');
        }

        const result = await response.json();
        if (result.success) {
            alert('Ride accepted successfully!');
            // Optionally, refresh the list or redirect
            gotodriverRecord(); // Redirect to records page after accepting ride
        } 
        else {
            alert('Error accepting ride');
        }
    } catch (error) {
        console.error('Error accepting ride:', error);
        alert('There was a problem accepting the ride');
    }
}