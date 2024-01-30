# Visitor Management System

Visitor Management System is an innovative, user-friendly platform designed to transform the way you welcome and manage guests. Tailored for businesses, institutions, and facilities of all sizes, this system simplifies visitor registration, approval, and tracking, ensuring a smooth and secure experience for both hosts and visitors.

## Table of Contents
- [Creating a New Visitor](#creating-a-new-visitor)
- [Approving a Visitor](#approving-a-visitor)
- [Changing User Password](#changing-user-password)
- [User Management](#user-management)
  - [Creating a New User](#creating-a-new-user)
  - [Updating User Information](#updating-user-information)
  - [Deleting a User Login](#deleting-a-user-login)
- [Generating Reports](#generating-reports)
- [Gate User Functions](#gate-user-functions)
  - [Managing Visitor Entrance](#managing-visitor-entrance)
  - [Managing Visitor Departure](#managing-visitor-departure)

## Creating a New Visitor
1. Click on the **New Visitor** icon (Create).
   ![Preview](/static/Preview.jpg)
   *New Visitor Form looks like this*
2. Fill required fields:
   - Visitor ID no is compulsory (use National ID No, Driving License No, or Passport No).
   - If you have a photo of the visitor, upload it (less than 100Kb).
3. Verify the final form.
4. Click **Save** if the information is correct.
5. Click **Cancel** if you do not wish to save.
   
## Approving a Visitor
1. Click on the **Approve Visitor** icon `→`.
   - Note: Requesters cannot approve their own requests.
2. Click on the relevant visitor number on the side panel.
3. If any information needs updating, mention it in the Remarks Field.
4. Click **Approve** if all information is correct; otherwise, click **Reject**.

## Changing User Password
1. Click on the **Change** icon.
2. Type the new password in both text boxes.
3. Click **Save**.

## User Management
### Creating a New User
1. Click on the **Manage** icon.
2. Click on **Create**.
3. Fill all fields with relevant information.
4. Select User level:
   - Admin – Can make changes except Gate user functions.
   - Approver - Can approve and create new visitor requests.
   - Requester – Can only request a new user.
   - Gate – Only Arrival & Departure functions are allowed.
5. Click **Register**.

### Updating User Information
1. Click on the relevant user record.
2. Change information as required.
3. Click **Save**.

### Deleting a User Login
1. Type the user name in the search box and click **Search** or click the checkbox next to the relevant user.
2. Click **Delete**.
3. Use **Select all** to delete all users at once.
4. Click the back arrow `←` to return to the dashboard.

## Generating Reports
1. Click on the Reports `→` icon.
2. Select the required report on the side panel:
   - User report – Generates a user list.
   - Visitor Reports – Generates a visitor list (select a start and end date).
3. Click **Export** to generate the Excel sheet.

## Gate User Functions
### Managing Visitor Entrance
1. Ask for the visitor number upon arrival.
2. Click on the Arrive Visitor `→` icon.
3. Click on the relevant visitor number.
4. Check the Visitor ID number.
5. Update the Remarks Field for any mismatch except the Visitor ID number.
6. Click **Arrived**.

### Managing Visitor Departure
1. Ask for the visitor number upon departure.
2. Click on the Departure Visitor `→` icon.
3. Click on the relevant visitor number.
4. Click **Departed**.
