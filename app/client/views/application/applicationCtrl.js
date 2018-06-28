angular.module("reg").controller("ApplicationCtrl", [
    "$scope",
    "$rootScope",
    "$state",
    "$http",
    "currentUser",
    "settings",
    "Session",
    "UserService",
    "$filter",

    function(
        $scope,
        $rootScope,
        $state,
        $http,
        currentUser,
        Settings,
        Session,
        UserService,
        $filter
    ) {
        // Set up the user
        $scope.user = currentUser.data;
        console.log($scope.user);
        // Is the student from MIT?
        // $scope.isMitStudent = $scope.user.email.split('@')[1] == 'mit.edu';

        // // If so, default them to adult: true
        // if ($scope.isMitStudent){
        //   $scope.user.profile.adult = true;
        // }

        // Populate the school dropdown
        // populateSchools();
        _setupForm();

        $scope.regIsClosed = Date.now() > Settings.data.timeClose;

        //-------------- Activities ----------
        $scope.activities = [
            { name: "Design", checked: false },
            { name: "Business", checked: false },
            { name: "Software", checked: false },
            { name: "Hardware", checked: false },
            { name: "Communication", checked: false },
            { name: "Natural Sciences", checked: false },
            { name: "Humanities", checked: false },
            { name: "Engineering", checked: false }
        ];
        $scope.otherActivity = "";

        if ($scope.user.profile.activities) {
            $scope.activities = $scope.activities.map(function(a) {
                if ($scope.user.profile.activities.indexOf(a.name) > -1) {
                    a.checked = true;
                }
                return a;
            });

            var allActivity = $scope.activities.map(function(a) {
                return a.name;
            });
            $scope.user.profile.activities.forEach(function(a) {
                if (allActivity.indexOf(a) == -1) {
                    $scope.otherActivity = a;
                }
            });
        }
        $scope.selectedActivity = function() {
            $scope.user.profile.activities = $filter("filter")(
                $scope.activities,
                { checked: true }
            )
                .map(function(a) {
                    return a.name;
                })
                .sort();
        };

        // ------------------------------- -------------------------------

        // ------------------------------- dietaryRestrictions -------------------------------

        $scope.dietaryRestrictions = [
            { name: "Vegetarian", checked: false },
            { name: "Vegan", checked: false },
            // {name: 'Halal', checked:false},
            // {name: 'Kosher', checked:false},
            { name: "Nut Allergy", checked: false }
        ];
        $scope.otherDietaryRestriction = "";

        if ($scope.user.profile.dietaryRestrictions) {
            $scope.dietaryRestrictions = $scope.dietaryRestrictions.map(
                function(a) {
                    if (
                        $scope.user.profile.dietaryRestrictions.indexOf(
                            a.name
                        ) > -1
                    ) {
                        a.checked = true;
                    }
                    return a;
                }
            );

            var allDietry = $scope.dietaryRestrictions.map(function(a) {
                return a.name;
            });
            $scope.user.profile.dietaryRestrictions.forEach(function(a) {
                if (allDietry.indexOf(a) == -1) {
                    $scope.otherDietaryRestriction = a;
                }
            });
        }
        $scope.selectedDietary = function() {
            $scope.user.profile.dietaryRestrictions = $filter("filter")(
                $scope.dietaryRestrictions,
                { checked: true }
            )
                .map(function(a) {
                    return a.name;
                })
                .sort();
        };

        // All this just for dietary restriction checkboxes fml

        // $scope.selectedDietary = function () {
        //     $scope.user.profile.dietaryRestrictions = $filter('filter')($scope.dietaryRestrictions, {checked: true}).map(function (a) {
        //       return a.name;
        //     }).sort();
        // }

        // ------------------------------- -------------------------------

        /**
         * TODO: JANK WARNING
         */
        // function populateSchools(){
        //   $http
        //     .get('/assets/schools.json')
        //     .then(function(res){
        //       var schools = res.data;
        //       var email = $scope.user.email.split('@')[1];

        //       if (schools[email]){
        //         $scope.user.profile.school = schools[email].school;
        //         $scope.autoFilledSchool = true;
        //       }
        //     });

        //   $http
        //     .get('/assets/schools.csv')
        //     .then(function(res){
        //       $scope.schools = res.data.split('\n');
        //       $scope.schools.push('Other');

        //       var content = [];

        //       for(i = 0; i < $scope.schools.length; i++) {
        //         $scope.schools[i] = $scope.schools[i].trim();
        //         content.push({title: $scope.schools[i]})
        //       }

        //       $('#school.ui.search')
        //         .search({
        //           source: content,
        //           cache: true,
        //           onSelect: function(result, response) {
        //             $scope.user.profile.school = result.title.trim();
        //           }
        //         })
        //     });
        // }

        function _updateUser(e) {
            // remove "other",if any, from dietary restrictions
            $scope.selectedDietary();
            // re-add it to the list
            if ($scope.otherDietaryRestriction !== "") {
                $scope.user.profile.dietaryRestrictions.push(
                    $scope.otherDietaryRestriction
                );
            }

            // remove "other",if any, from activities
            $scope.selectedActivity();
            // re-add it to the list
            if ($scope.otherActivity !== "") {
                $scope.user.profile.activities.push($scope.otherActivity);
            }

            UserService.updateProfile(Session.getUserId(), $scope.user.profile)
                .success(function(data) {
                    sweetAlert(
                        {
                            title: "Awesome!",
                            text: "Your profile has been saved.",
                            type: "success",
                            confirmButtonColor: "#e76482"
                        },
                        function() {
                            $rootScope.currentUser = data;
                            $state.go("app.dashboard");
                        }
                    );
                })
                .error(function(res) {
                    sweetAlert("Uh oh!", "Something went wrong.", "error");
                });
        }

        function isMinor() {
            return !$scope.user.profile.adult;
        }

        function minorsAreAllowed() {
            return Settings.data.allowMinors;
        }

        function minorsValidation() {
            // Are minors allowed to register?
            if (isMinor() && !minorsAreAllowed()) {
                return false;
            }
            return true;
        }

        function _setupForm() {
            // Custom minors validation rule
            $.fn.form.settings.rules.allowMinors = function(value) {
                return minorsValidation();
            };

            // Semantic-UI form validation
            $(".ui.form").form({
                inline: true,
                fields: {
                    shirt: {
                        identifier: "shirt",
                        rules: [
                            {
                                type: "empty",
                                prompt: "Please give us a shirt size!"
                            }
                        ]
                    },

                    name: {
                        identifier: "name",
                        rules: [
                            {
                                type: "empty",
                                prompt: "Please enter your name."
                            }
                        ]
                    }
                    // school: {
                    //   identifier: 'school',
                    //   rules: [
                    //     {
                    //       type: 'empty',
                    //       prompt: 'Please enter your school name.'
                    //     }
                    //   ]
                    // },
                    // year: {
                    //   identifier: 'year',
                    //   rules: [
                    //     {
                    //       type: 'empty',
                    //       prompt: 'Please select your graduation year.'
                    //     }
                    //   ]
                    // },
                    // gender: {
                    //   identifier: 'gender',
                    //   rules: [
                    //     {
                    //       type: 'empty',
                    //       prompt: 'Please select a gender.'
                    //     }
                    //   ]
                    // },
                    // adult: {
                    //   identifier: 'adult',
                    //   rules: [
                    //     {
                    //       type: 'allowMinors',
                    //       prompt: 'You must be an adult, or an MIT student.'
                    //     }
                    //   ]
                    // }
                }
            });
        }

        $scope.submitForm = function() {
            if ($(".ui.form").form("is valid")) {
                _updateUser();
            } else {
                sweetAlert(
                    "Uh oh!",
                    "Please Fill The Required Fields",
                    "error"
                );
            }
        };
    }
]);
