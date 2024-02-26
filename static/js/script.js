$(document).ready(function() {
    $('#instagram_form').on('submit', function(event) {
        event.preventDefault();
        $('#loadingModal').modal('show');
    });
});