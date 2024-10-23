function Acceptedride(bookingId) {
    var xhr = new XMLHttpRequest();
    var url = '/acceptedride';
    xhr.open('POST', url, true);
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.onreadystatechange = function () {
        if (xhr.readyState === XMLHttpRequest.DONE) {
            if (xhr.status === 200) {
                // Handle success, maybe show a confirmation message
                console.log('Ride accepted successfully!');
            } else {
                // Handle error
                console.error('Failed to accept ride:', xhr.statusText);
            }
        }
    };
    xhr.onerror = function () {
        console.error('Error accepting ride:', xhr.statusText);
    };
    var data = JSON.stringify({ bookingId: bookingId });
    xhr.send(data);
    fetch('/acceptedride', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ bookingId: bookingId })
    })
    .then(response => {
        if (response.ok) {
            // Handle success, maybe show a confirmation message
            console.log('Ride accepted successfully!');
        } else {
            // Handle error
            console.error('Failed to accept ride:', response.statusText);
        }
    })
    .catch(error => {
        console.error('Error accepting ride:', error);
    });
}
