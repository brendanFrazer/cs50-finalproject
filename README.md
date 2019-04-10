For my CS50x Final Project I created a web application named outWork which can be used to keep track of workouts and exercises and shows your progress.
I used a combination of Python, Matplotlib, Flask/Jinja, SQLite, HTML, Javascript, along with a touch of CSS and Bootstrap.

You can register as a new user and then add your own exercise routines by selecting 'Manage Routines' from the dropdown menu in the top right. You can also delete routines from this screen.
Once you've created a routine, you can add exercises to it by clicking on 'Manage Exercises' from the dropdown menu. You can also remove any exercises you wish.
On your home screen you will see all of the workout routines you have created. When you click on one, a dropdown will occur and you can see all of the exercises in that routine.
For each exercise, you'll have an input field for "sets", "reps", and "weight", along with a button to log that exercise. These fields will default to "0" if you have not logged an exercise for them yet.
Once you have logged your first workout, the previous values that you submitted for sets, reps, and weight will be shown (as a placeholder).
If you've logged a workout for an exercise you can view your progress on the 'Progress Graph' page.
As you log more workouts, this will update and track the amount of weight you did for each exercise, along with the date, to show your progression over time.