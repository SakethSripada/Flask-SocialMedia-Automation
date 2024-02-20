document.getElementById('sendVerifEmail').addEventListener('click', function() {
            let email = document.querySelector('input[name="email"]').value;
            let csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
            fetch('/send-verification-email', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify({email: email}),
            })
            .then(response => {
                if (response.ok) {
                    return response.json();
                }
                throw new Error('Network response was not ok.');
            })
            .then(data => {
                alert(data.message);
            })
            .catch((error) => {
                console.error('Error:', error);
                alert('Error sending verification email.');
            });
        });