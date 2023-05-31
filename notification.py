import calendar
from datetime import date
from datetime import timedelta

from flask_mail import Message
from sqlalchemy import true


def schedule_notification(event, time_delta):
    notification_date = event.date - time_delta

    # Check if the event should be notified weekly
    if event.weekly_notification:
        notification_date = event.date - time_delta
        scheduler.add_job(send_notification, 'date', run_date=notification_date, args=[event.id])

    # Check if the event should be notified monthly
    if event.monthly_notification:
        next_occurrence = event.date + time_delta
        scheduler.add_job(send_notification, 'date', run_date=next_occurrence, args=[event.id])


def get_upcoming_events(user):
    today = date.today()
    next_seven_days = today + timedelta(days=7)

    upcoming_events = Event.query.filter(
        Event.user_id == user.id,
        (Event.date >= today) | ((Event.date < today) & (Event.weekly_notification == true())) | (
                (Event.date < today) & (Event.monthly_notification == true()))
    ).all()

    return upcoming_events


def get_weekly_notifications(user):
    today = date.today()
    next_seven_days = today + timedelta(days=7)

    weekly_events = Event.query.filter(
        Event.user_id == user.id
    ).all()

    weekly_notifications = {}

    for event in weekly_events:
        notification_day = event.user.notification_day.lower()
        if notification_day not in weekly_notifications:
            weekly_notifications[notification_day] = []
        weekly_notifications[notification_day].append(event)

    upcoming_weekly_events = []

    for notification_day, events in weekly_notifications.items():
        for event in events:
            event_date = event.date
            while event_date <= next_seven_days:
                if today <= event_date:
                    upcoming_weekly_events.append(event)
                event_date += timedelta(days=7)

    upcoming_weekly_events.sort(key=lambda x: x.date)

    return upcoming_weekly_events


def get_monthly_notifications(user):
    today = date.today()
    next_seven_days = today + timedelta(days=7)

    monthly_events = Event.query.filter(
        Event.user_id == user.id
    ).all()

    upcoming_monthly_events = []

    for event in monthly_events:
        event_date = event.date
        while event_date <= next_seven_days:
            if today <= event_date:
                upcoming_monthly_events.append(event)
            # Calculate the next occurrence by adding one month to the event date
            year = event_date.year + (event_date.month + 1) // 12
            month = (event_date.month + 1) % 12 or 12
            day = min(event_date.day, calendar.monthrange(year, month)[1])
            event_date = event_date.replace(year=year, month=month, day=day)

    upcoming_monthly_events.sort(key=lambda x: x.date)

    return upcoming_monthly_events


def send_notification(event_id):
    event = Event.query.get(event_id)
    user = event.user

    # Get the event value
    event_value = event.money

    # Create the email message
    msg = Message("Event Notification", recipients=[user.email])

    # Render the email template with the event details
    msg.html = render_template(
        "notification_email.html",
        event=event,
        event_value=event_value
    )

    # Send the email
    mail.send(msg)
